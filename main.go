package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	iptables "github.com/coreos/go-iptables/iptables"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	watchtools "k8s.io/client-go/tools/watch"
)

//OutSideCluster - defines the type of connectivity to use
var OutSideCluster bool

var previousConfig map[string]string

const plndrConfigMap = "plndr"

func main() {
	flag.CommandLine.BoolVar(&OutSideCluster, "outsideCluster", false, "Use ~/.kube/config to run starboard")
	flag.Parse()

	var clientset *kubernetes.Clientset
	if OutSideCluster == false {
		// This will attempt to load the configuration when running within a POD
		cfg, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("error creating kubernetes client config: %s", err.Error())
		}
		clientset, err = kubernetes.NewForConfig(cfg)

		if err != nil {
			log.Fatalf("error creating kubernetes client: %s", err.Error())
		}
		// use the current context in kubeconfig
	} else {
		config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(os.Getenv("HOME"), ".kube", "config"))
		if err != nil {
			panic(err.Error())
		}
		clientset, err = kubernetes.NewForConfig(config)

		if err != nil {
			log.Fatalf("error creating kubernetes client: %s", err.Error())
		}
	}

	// TODO - Needs changing to (with cancel)
	//ctx := context.TODO()
	previousConfig = make(map[string]string)
	// Build a options structure to defined what we're looking for
	listOptions := metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", plndrConfigMap),
	}
	// Watch function
	// Use a restartable watcher, as this should help in the event of etcd or timeout issues
	rw, err := watchtools.NewRetryWatcher("1", &cache.ListWatch{
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return clientset.CoreV1().ConfigMaps("kube-system").Watch(listOptions)
		},
	})

	if err != nil {
		log.Fatalf("error creating watcher: %s", err.Error())
	}

	ch := rw.ResultChan()
	defer rw.Stop()
	log.Infof("Beginning watching Kubernetes configMap [%s]", plndrConfigMap)

	i, err := iptables.New()
	if err != nil {
		log.Fatalf("error creating iptables client : %s", err.Error())
	}

	signalChan := make(chan os.Signal, 1)

	// Add Notification for Userland interrupt
	signal.Notify(signalChan, syscall.SIGINT)

	// Add Notification for SIGTERM (sent from Kubernetes)
	signal.Notify(signalChan, syscall.SIGTERM)

	// Add Notification for SIGKILL (sent from Kubernetes)
	signal.Notify(signalChan, syscall.SIGKILL)

	go func() {
		for event := range ch {

			// We need to inspect the event and get ResourceVersion out of it
			switch event.Type {
			case watch.Added, watch.Modified:
				// A Modification event has been triggered
				log.Debugf("ConfigMap [%s] has been Created or modified", plndrConfigMap)
				cm, ok := event.Object.(*v1.ConfigMap)
				if !ok {
					log.Errorf("Unable to parse ConfigMap from watcher")
					break
				}

				// Grab all of the configurations we're aware of, we can then compare to the update to find any that have been deleted
				var previousEntries, currentEntries []string
				for k := range previousConfig {
					previousEntries = append(previousEntries, k)
				}

				// Iterate through the cidr configurations
				for k, v := range cm.Data {

					if strings.HasPrefix(k, "cidr-") {
						log.Infof("Processing configuration [%s] with cidr [%s]", k, v)

						// Grab all of the entries in the configmap
						currentEntries = append(currentEntries, k)

						// Check if the rule already exists in the iptables configuration
						comment := fmt.Sprintf("kube-vip rule for [%s]", k)

						ruleExists, err := i.Exists("nat", "PREROUTING", "-d", v, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
						if err != nil {
							log.Fatalf("Unable to verify updated cidr configuration: %s", err.Error())
						}

						// if the rule doesn't exist,and a previous rule does we need to clear the old rule
						if ruleExists == false && previousConfig[k] != "" {
							comment := fmt.Sprintf("kube-vip rule for [%s]", k)

							previousRuleExists, err := i.Exists("nat", "PREROUTING", "-d", previousConfig[k], "-j", "ACCEPT", "-m", "comment", "--comment", comment)
							if err != nil {
								log.Warnf("error checking for previous cidr [%s], safe to ignore", previousConfig[k], "-m", "comment", "--comment", comment)
							} else {
								if previousRuleExists == true {
									err = i.Delete("nat", "PREROUTING", "-d", previousConfig[k], "-j", "ACCEPT", "-m", "comment", "--comment", comment)
									if err != nil {
										log.Fatalf("error removing previous cidr [%s]: %s", previousConfig[k], err.Error())
									}
									log.Infof("Removed previous rule for cidr [%s]", previousConfig[k])
								}
							}
						}

						// If the rule doesn't exist, we need to add it
						if !ruleExists {
							log.Warnf("Not found iptables rule for load-balancer cidr [%s]", v)
							comment := fmt.Sprintf("kube-vip rule for [%s]", k)
							err = i.Insert("nat", "PREROUTING", 1, "-d", v, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
							if err != nil {
								log.Fatalf("error creating cidr rule: %s", err.Error())
							}
							log.Infof("Updated configuration with new cidr [%s]", v)
						}
						// Store the previous configuration so we can remove if needed
						previousConfig[k] = v
					}
				}
				// Remove the outliers, this will compare the previous configuration with the new and remove any entries from the iptables rules (if they exist)
				for x := range previousEntries {
					var found bool
					for y := range currentEntries {
						if previousEntries[x] == currentEntries[y] {
							found = true
						}
					}
					// If it's not found in the new rules then it requires removing, as it's been removed from teh configMap
					if found == false {
						comment := fmt.Sprintf("kube-vip rule for [%s]", previousEntries[x])

						previousRuleExists, err := i.Exists("nat", "PREROUTING", "-d", previousConfig[previousEntries[x]], "-j", "ACCEPT", "-m", "comment", "--comment", comment)
						if err != nil {
							log.Warnf("error checking for previous cidr [%s], safe to ignore", previousConfig[previousEntries[x]], "-m", "comment", "--comment", comment)
						} else {
							if previousRuleExists == true {
								err = i.Delete("nat", "PREROUTING", "-d", previousConfig[previousEntries[x]], "-j", "ACCEPT", "-m", "comment", "--comment", comment)
								if err != nil {
									log.Fatalf("error removing previous cidr [%s]: %s", previousConfig[previousEntries[x]], err.Error())
								}
								log.Infof("Removed previous rule for cidr [%s]", previousConfig[previousEntries[x]])
							}
						}
						// Remove from the configuration map
						delete(previousConfig, previousEntries[x])
					}
				}

			case watch.Deleted:
				log.Debugf("ConfigMap [%s] has been Deleted", plndrConfigMap)
				// Loop through map and tidy
				for k, v := range previousConfig {
					// Attempt to remove the existing rule
					comment := fmt.Sprintf("kube-vip rule for [%s]", k)

					previousRuleExists, err := i.Exists("nat", "PREROUTING", "-d", v, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
					if err != nil {
						log.Warnf("error checking for cidr [%s], safe to ignore (rule may need manually cleaning", v)
					} else {
						if previousRuleExists == true {
							err = i.Delete("nat", "PREROUTING", "-d", v, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
							if err != nil {
								log.Fatalf("error removing cidr [%s] fo [%s]: %s", v, k, err.Error())
							}
							log.Infof("Removed rule for cidr [%s]", k)
						}
					}
				}
			case watch.Bookmark:
				// Un-used
			case watch.Error:
				log.Infoln("err")

				// This round trip allows us to handle unstructured status
				errObject := apierrors.FromObject(event.Object)
				statusErr, ok := errObject.(*apierrors.StatusError)
				if !ok {
					log.Fatalf(spew.Sprintf("Received an error which is not *metav1.Status but %#+v", event.Object))
					// Retry unknown errors

				}

				status := statusErr.ErrStatus
				log.Errorf("%v", status)

			default:
			}
		}
	}()
	<-signalChan

	// Loop through map and tidy
	for k, v := range previousConfig {
		// Attempt to remove the existing rule
		comment := fmt.Sprintf("kube-vip rule for [%s]", k)
		log.Debugf("Evaluating rule [%s]")
		previousRuleExists, err := i.Exists("nat", "PREROUTING", "-d", v, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
		if err != nil {
			log.Warnf("error checking for cidr [%s], safe to ignore (rule may need manually cleaning", v)
		} else {
			if previousRuleExists == true {
				err = i.Delete("nat", "PREROUTING", "-d", v, "-j", "ACCEPT", "-m", "comment", "--comment", comment)
				if err != nil {
					log.Fatalf("error removing cidr [%s] fo [%s]: %s", v, k, err.Error())
				}
				log.Infof("Removed rule for cidr [%s]", k)
			}
		}
	}

	log.Infof("Shutting down starboard")
}
