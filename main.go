package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

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

//previousCidr - this is used to determine if the existing rule needs deleting
var previousCidr string

const plndrConfigMap = "plndr-configmap"

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

	// Build a options structure to defined what we're looking for
	listOptions := metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", plndrConfigMap),
	}
	// Watch function
	// Use a restartable watcher, as this should help in the event of etcd or timeout issues
	rw, err := watchtools.NewRetryWatcher("1", &cache.ListWatch{
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return clientset.CoreV1().ConfigMaps("default").Watch(listOptions)
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
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for event := range ch {

			// We need to inspect the event and get ResourceVersion out of it
			switch event.Type {
			case watch.Added, watch.Modified:
				log.Debugf("ConfigMap [%s] has been Created or modified", plndrConfigMap)
				cm, ok := event.Object.(*v1.ConfigMap)
				if !ok {
					log.Errorf("Unable to parse ConfigMap from watcher")
					break
				}
				cidr := cm.Data["cidr"]
				log.Infof("Found %s services defined in ConfigMap", cidr)

				ruleExists, err := i.Exists("nat", "PREROUTING", "-d", cidr, "-j", "ACCEPT")
				if err != nil {
					log.Fatalf("Unable to verify updated cidr configuration: %s", err.Error())
				}

				if ruleExists == true && previousCidr != "" {
					// Check if a previous rule exists, if it does we should remove it
					previousRuleExists, err := i.Exists("nat", "PREROUTING", "-d", previousCidr, "-j", "ACCEPT")
					if err != nil {
						log.Warnf("error checking for previous cidr [%s], safe to ignore", previousCidr)
					} else {
						if previousRuleExists == true {
							err = i.Delete("nat", "PREROUTING", "-d", previousCidr, "-j", "ACCEPT")
							if err != nil {
								log.Fatalf("error removing previous cidr [%s]: %s", previousCidr, err.Error())
							}
							log.Infof("Removed previous rule for cidr [%s]", previousCidr)
						}
					}

				}
				if !ruleExists {
					log.Warnf("Not found iptables rule for load-balancer cidr [%s]", cidr)
				}

				err = i.Insert("nat", "PREROUTING", 1, "-d", cidr, "-j", "ACCEPT")
				if err != nil {
					log.Fatalf("error creating cidr rule: %s", err.Error())
				}
				log.Infof("Updated configuration with new cidr [%s]", cidr)
				previousCidr = cidr

			case watch.Deleted:
				log.Debugf("ConfigMap [%s] has been Deleted", plndrConfigMap)
				// Attempt to remove the previous rule
				previousRuleExists, err := i.Exists("nat", "PREROUTING", "-d", previousCidr, "-j", "ACCEPT")
				if err != nil {
					log.Warnf("error checking for cidr [%s], safe to ignore (rule may need manually cleaning", previousCidr)
				} else {
					if previousRuleExists == true {
						err = i.Delete("nat", "PREROUTING", "-d", previousCidr, "-j", "ACCEPT")
						if err != nil {
							log.Fatalf("error removing cidr [%s]: %s", previousCidr, err.Error())
						}
						log.Infof("Removed rule for cidr [%s]", previousCidr)
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

	// Attempt to remove the previous rule
	previousRuleExists, err := i.Exists("nat", "PREROUTING", "-d", previousCidr, "-j", "ACCEPT")
	if err != nil {
		log.Warnf("error checking for cidr [%s], safe to ignore (rule may need manually cleaning", previousCidr)
	} else {
		if previousRuleExists == true {
			err = i.Delete("nat", "PREROUTING", "-d", previousCidr, "-j", "ACCEPT")
			if err != nil {
				log.Fatalf("error removing cidr [%s]: %s", previousCidr, err.Error())
			}
			log.Infof("Removed rule for cidr [%s]", previousCidr)
		}
	}

	log.Infof("Shutting down starboard")
}
