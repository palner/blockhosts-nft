package bhnft

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/apiban/nftlib"
)

func AddIP(list []string, value string) []string {
	if value == "0.0.0.0" {
		return list
	}

	if Contains(list, value) {
		return list
	}

	list = append(list, value)
	return list
}

func BeenAWeek(ts int64) bool {
	checkTime := time.Unix(ts, 0)
	timeNow := time.Now()
	oneWeekAgo := timeNow.AddDate(0, 0, -7)

	if checkTime.Before(oneWeekAgo) {
		return true
	}

	return false

}

// Function to see if string within string
func Contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

// Function to see if string within string
func ContainsIP(cidrstring string, ip string) bool {
	_, netw, err := net.ParseCIDR(cidrstring)
	if err != nil {
		return false
	}

	ipaddress := net.ParseIP(ip)
	if ipaddress == nil {
		return false
	}

	if netw.Contains(ipaddress) {
		return true
	}

	return false
}

func GetTime() int64 {
	now := time.Now()
	sec := now.Unix()
	return sec
}

func AddSet(setName string) error {
	log.Println("** Attempting to add set and rules")
	log.Println("[-] finding input chains")
	inputChains, err := nftlib.NftGetInputChains()
	if err != nil {
		log.Println("[x] error finding input chain:", err.Error())
		return errors.New("error finding an input chain")
	}

	log.Println("[.] found", inputChains)
	chainDetails, err := nftlib.NftGetChainDetails(inputChains[0])
	if err != nil {
		log.Println("[x] error finding input chain details:", err.Error())
		return errors.New("error getting input chain details")
	}

	log.Println("[.] creating set", setName, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSet(chainDetails, setName)
	if err != nil {
		log.Println("[x] unable to create set:", err.Error())
		return errors.New("unable to create set")
	}

	log.Println("[.] creating input rule", setName, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRuleInput(chainDetails, setName)
	if err != nil {
		log.Println("[*] unable to create input rule:", err.Error())
		log.Println("[*] input rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", setName, "SET")
	}

	log.Println("[-] finding output chains")
	outputchains, err := nftlib.NftGetOutputChains()
	if err != nil {
		log.Println("[x] error finding output chain:", err.Error())
		return nil
	}

	log.Println("[.] found", outputchains)
	chainDetails, err = nftlib.NftGetChainDetails(outputchains[0])
	if err != nil {
		log.Println("[x] error finding output chain details:", err.Error())
		return nil
	}

	log.Println("[.] creating output rule", setName, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRuleOutput(chainDetails, setName)
	if err != nil {
		log.Println("[*] unable to create output rule:", err.Error())
		log.Println("[*] output rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", setName, "SET")
	}

	return nil
}

func RemoveElement(element string, array []string) []string {
	for i, v := range array {
		if v == element {
			return append(array[:i], array[i+1:]...)
		}
	}
	return array
}
