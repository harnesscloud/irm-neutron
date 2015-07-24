#!/usr/bin/env python

import requests, json, subprocess
from bottle import route, run,response,request
import ConfigParser, optparse
import logging
import logging.handlers as handlers
import socket

#Config and format for logging messages
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt = '%(asctime)s.%(msecs)d - %(levelname)s : %(filename)s - %(funcName)s : %(message)s', datefmt = '%d/%m/%Y %H:%M:%S')
handler = handlers.TimedRotatingFileHandler("n-irm.log", when = "H", interval = 24, backupCount = 0)
## Logging format
handler.setFormatter(formatter)
logger.addHandler(handler)

################################## CLI Stuff - Start ##################################

def init(interface):
  global CONFIG
  if 'CONFIG' not in globals():
    CONFIG = ConfigParser.RawConfigParser()
    CONFIG.read('irm.cfg')
  global IP_ADDR
  if CONFIG.has_option('main', 'IRM_ADDRESS') and CONFIG.get('main', 'IRM_ADDRESS') != "":
    IP_ADDR = CONFIG.get('main', 'IRM_ADDRESS')
  elif interface != "":
    IP_ADDR = getifip(interface)
  else:
    IP_ADDR = "0.0.0.0"
  global HOST_NAME
  HOST_NAME = socket.gethostname()
  global TYPE
  TYPE = "Network"


def main():
 usage = "Usage: %prog [option] arg"
 #paragraph of help text to print after option help
 epilog = "Copyright 2015 SAP Ltd"
 #A paragraph of text giving a brief overview of your program
 description="IRM is small api that does something"
 parser = optparse.OptionParser(usage = usage, epilog = epilog, description = description)

 parser.add_option('-v','--version', action = 'store_true', default = False, dest = 'version', help = 'show version information')
 parser.add_option('-i', '--interface', action = 'store', type = "string", default = False, dest = 'interface', help = 'network interface to start the API')
 parser.add_option('-p', '--port', action = 'store', default = False, dest = 'port', help = 'port to start the API')
 parser.add_option('-c', '--config', action = 'store', default = False, dest = 'config', help = 'config file to run the IRM-net in daemon mode')

 options, args = parser.parse_args()
 #print options, args
 if options.version:
     VERSION = "0.1"
     print VERSION
     sys.exit(1)

 global PORT_ADDR
 if options.config:
    global CONFIG
    CONFIG = ConfigParser.RawConfigParser()
    CONFIG.read(options.config)

    INTERFACE = CONFIG.get('main', 'IRM_INTERFACE')
    PORT_ADDR = CONFIG.get('main', 'IRM_PORT')
 else:

    if options.interface:
       INTERFACE = options.interface
    else:
       INTERFACE = "eth0"
       print "No interface specified, using " + INTERFACE + " as default"

    if options.port:
       PORT_ADDR = options.port
    else:
       PORT_ADDR = 5050
       print "No port specified, using " + str(PORT_ADDR) + " as default"

 try:
    init(INTERFACE)
    print "Initialization done"
    startAPI(IP_ADDR, PORT_ADDR)
 except Exception, e:
    e = sys.exc_info()[1]
    print "Error", e


def noExtraOptions(options, *arg):
    options = vars(options)
    for optionValue in options.values():
        print optionValue
        if not (optionValue == False):
            print "Bad option combination"
            sys.exit()

################################## CLI Stuff - End ####################################
################################## API Stuff - Start ##################################

@route('/getResources/', method = 'GET')
@route('/getResources', method = 'GET')
def getResources():
  logger.info("Called")

  try:
      availableFloatingIPs = getAvailableFloatingIPs()
      r = {"Resources" : {"NetworkID-PublicIP" : {"Type" : "PublicIP", "IpPool" : availableFloatingIPs}}}
      result = json.dumps(r)

  except Exception.message, e:
     response.status = 400
     error = {"message" : e, "code" : response.status}
     logger.error(error)
     return error

  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')

  logger.info("Completed")
  return result


@route('/getAllocSpec/', method = 'GET')
@route('/getAllocSpec', method = 'GET')
def getAllocSpec():
  logger.info("Called")
  
  PublicIP = {"IP": { "Description": "IP address", "DataType": "string"}, "VM": { "Description": "VM to apply the public IP", "DataType": "string" }}
  Subnet = {"AddressRange" : { "Description" : "Address range", "DataType": "string" }, "VMs": { "Description": "VMs that belong to this subnet",  "DataType": "list<string>" }}
  Firewall = {"VMs": { "Description": "VMs that belong", "DataType": "list<string>" }}

  r = {"Types" : {"PublicIP": PublicIP, "Subnet": Subnet, "Firewall": Firewall}}
  result = json.dumps(r)

  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')

  logger.info("Completed")
  return result


#Expects three lists (Resource, Allocation and Release) containing the ID's of neutron entries
@route('/computeCapacity/', method='POST')
@route('/computeCapacity', method='POST')
def computeCapacity():
  logger.info("Called")

  try:
    req = json.load(request.body)
  except ValueError as e:
    response.status = 400
    error = "computeCapacity was not supplied with a correct payload"
    logger.error(error)
    return error

  resources = req.get("Resource")
  allocations = req.get("Allocation")
  releases = req.get("Release")
  
  resources = resources + list(set(releases) - set(resources))
  resources = [entry for entry in resources if entry not in allocations]

  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')

  logger.info("Completed")
  
  return {"Resource": resources}


#Expects a list of dictionaries containing "VirtualMachine" (ID/name of VM) and "floatingIP" (floatingIP to assign) 
@route('/createReservation/', method='POST')
@route('/createReservation', method='POST')
def createReservation():
  logger.info("Called")

  try:
    req = json.load(request.body)
  except ValueError:
    response.status = 400
    error = "createReservation was not supplied with a correct payload"
    logger.error(error)
    return error

  try:
    allocations = req.get("Allocation")
    availableFloatingIPs = getAvailableFloatingIPs()
    availableSubnets = getAvailableSubnets()
    print "availableFloatingIPs",availableFloatingIPs
    print "availableSubnets",availableSubnets
    reservations = []
    
    for allocation in allocations:
      typeN = allocation['Type']
      
      #print "vmID",vmID
      #print "floatingIP",floatingIP

      print "typeN",typeN
      
      if typeN == "PublicIP":
        vmID = allocation.get("Attributes").get("VM")
        floatingIP = allocation.get("Attributes").get("IP")
        print "VM",vmID
        print "IP",floatingIP

        if floatingIP in availableFloatingIPs:
          novaIn = ["nova", "add-floating-ip", vmID, floatingIP]
          process = subprocess.Popen(novaIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          novaOut, novaErr = process.communicate()
          
          availableFloatingIPs = getAvailableFloatingIPs()
          if floatingIP in availableFloatingIPs: #If IP still available then it wasn't properly added to VM
            raise Exception("IP not associated to VM")
          else:
            reservations.append(getIDFromFloatingIP(floatingIP))
          
        else:
          raise Exception("floatingIP not available")
      elif typeN == "Subnet":
        name = "HARNESS-"+allocation.get("ID")
        cidr = allocation.get("Attributes").get("AddressRange")

        print "cidr",cidr
        
        if cidr not in availableSubnets:
          neutronIn = ["neutron", "subnet-create", "demo-net", "--name", name, cidr]
          process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          neutronOut, neutronErr = process.communicate()

          if (neutronOut.find("Created a new subnet") != -1):
            neutronOut = neutronOut.splitlines()
            reservations.append([x for x in neutronOut if " id " in x][0].split("|")[2].strip())  #Extract the subnet id from the returned string and add to array
          else:
            reservations.append("ERROR (see logs)- Couldn't create " + allocation.get("ID") + " @ " + allocation.get("Attributes").get("AddressRange"))  #FIX ME - Waht should I do if failure
            logger.error(neutronErr)
            raise Exception(neutronErr)
        else:
          raise Exception("cidr already used")

      #reservations = {"Reservations": reservations}
      
      #response.set_header('Content-Type', 'application/json')
      #response.set_header('Accept', '*/*')
      #response.set_header('Allow', 'GET, HEAD')
      
      #logger.info("Completed")
      #return subnetIDS

      
  #except Exception.message,e:
  #  print "unable to process the request",e
    #logger.error("Unable to reserve floating ip " + floatingIP + " for " + vmID)
    #reservations.append("Unable to add ip " + floatingIP + " to " + vmID + ". Check VM and IP exist and are unnassigned")
  #except StandardError,e:
  #  print "Unable to create subnet",e
    #logger.error("Unable to reserve floating ip " + floatingIP + " for " + vmID)
    #reservations.append("Unable to add ip " + floatingIP + " to " + vmID + ". Check VM and IP exist and are unnassigned")
  except Exception,e:
    error = "unable to process the request: ",e
    print error
    logger.error(error)

  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')
    
  logger.info("Completed")
  return {"ReservationID": reservations}


@route('/checkReservation/', method='POST')
@route('/checkReservation', method='POST')
def checkReservation():
  logger.info("Called")

  try:
    req = json.load(request.body)
  except ValueError as e:
    response.status = 400
    error = "checkReservation was not supplied with a correct payload"
    logger.error(error)
    return error

  try:
    reservationIDs = req.get("ReservationID")
    reservations = {}

    for reservationID in reservationIDs:
      reservation = {}
      neutronEntry = getFIPEntryFromID(reservationID)

      if neutronEntry:
        reservation["Ready"] = False
        #if (neutronEntry != False):
        if (neutronEntry["fixedIP"] != ""):
          reservation["Address"] = neutronEntry["floatingIP"]
          reservation["Ready"] = True
        #else:
        #  reservation["ERROR"] = "No matching reservation for " + reservationID
      else:
        neutronEntry = getSubnetEntryFromID(reservationID)
        if neutronEntry:
          #reservation["Ready"] = False
          #if (neutronEntry != False):
          #if (neutronEntry["fixedIP"] != ""):
          reservation["ID"] = neutronEntry["name"]
          reservation["AddressRange"] = neutronEntry["cidr"]
          reservation["Ready"] = True
        else:
          reservation["ERROR"] = "No matching reservation for " + reservationID
        
      reservations[reservationID] = reservation
      
    reservations = {"Instances" : reservations}

    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'GET, HEAD')

    logger.info("Completed")
    return reservations

  except:
    error = "checkReservation ran into an error, please check payload"
    logger.error(error)
    response.status = 400
    return error


@route('/releaseReservation/', method='DELETE')
@route('/releaseReservation', method='DELETE')
def releaseReservation():
  logger.info("Called")

  try:
    #print ID
    req = json.load(request.body)
  except ValueError:
    response.status = 400
    error =  "releaseReservation was not supplied with a correct payload"
    return error
    logger.error(error)

  try:
    reservationIDs = req.get("ReservationID")
    availableFloatingIPIDs = getAvailableFloatingIPIDs()
    availableSubnetsIDs = getAvailableSubnetsIDs()
    
    for reservationID in reservationIDs:
      if reservationID in availableSubnetsIDs:
        deleteSubnet(reservationID)
      elif reservationID in availableFloatingIPIDs:
       disassociateFloatingIP(reservationID)
    
    logger.info("Completed")
    return {"result":{}}

  except Exception.message,e:
    print e
    msg = "releaseReservation didn't execute properly, please check payload and neutron status"
    print msg
    logger.error(msg)
    response.status = 400
    error = {"message":msg,"code":response.status}
    return error


@route('/releaseAllReservations/', method='DELETE')
@route('/releaseAllReservations', method='DELETE')
def releaseAllReservations():
  logger.info("Called")
  
  neutronFIPEntries = getNeutronFIPEntries()
  neutronSubnetsEntries = getAvailableSubnets()

  for subnet in neutronSubnetsEntries:
    if "HARNESS" in subnet.get('name'):
      deleteSubnet(subnet.get('ID'))

  for neutronEntry in neutronFIPEntries:
    if neutronEntry["fixedIP"] != "":
      disassociateFloatingIP(neutronEntry["ID"])
  
  logger.info("Completed")
  return {"result":{}}

############################## reserveResources method from irm-net for creating subnets ##############################

@route('/reserveResources/', method='POST')
@route('/reserveResources', method='POST')
def reserveResources():
  logger.info("Called")
  import subprocess
  
  try:
    #print ID
    req = json.load(request.body)
  except ValueError:
    response.status = 400
    error = "reserveResources was not supplied with a payload, please enter desired payload"
    logger.error(error)
    return error

  try:
    reserveResource = req['Allocation']
    #print reserveResource
    #print reserveResource['ID']
    #print reserveResource['Attributes']['AddressRange']

    subnetIDS = []
    #for reserveResource in reserveResources:
    neutronIn = ["neutron", "subnet-create", "demo-net", "--name", reserveResource['ID'], reserveResource['Attributes']['AddressRange']]
    process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    neutronOut, neutronErr = process.communicate()


    
    # ##FOR TESTING - REMOVE! ##
    # neutronOut = "Created a new subnet:\n"
    # neutronOut += "+------------------+--------------------------------------------------+\n"
    # neutronOut += "| Field            | Value                                            |\n"
    # neutronOut += "+------------------+--------------------------------------------------+\n"
    # neutronOut += "| allocation_pools | {\"start\": \"192.168.2.2\", \"end\": \"192.168.2.254\l\"} |\n"
    # neutronOut += "| cidr             | 192.168.2.0/24                                   |\n"
    # neutronOut += "| dns_nameservers  |                                                  |\n"
    # neutronOut += "| enable_dhcp      | True                                             |\n"
    # neutronOut += "| gateway_ip       | 192.168.2.1                                      |\n"
    # neutronOut += "| host_routes      |                                                  |\n"
    # neutronOut += "| id               | 15a09f6c-87a5-4d14-b2cf-03d97cd4b456             |\n"
    # neutronOut += "| ip_version       | 4                                                |\n"
    # neutronOut += "| name             | subnet1                                          |\n"
    # neutronOut += "| network_id       | 2d627131-c841-4e3a-ace6-f2dd75773b6d             |\n"
    # neutronOut += "| tenant_id        | 3671f46ec35e4bbca6ef92ab7975e463                 |\n"
    # neutronOut +=  "+------------------+--------------------------------------------------+"
    # ##FOR TESTING FIX ME - REMOVE! ##
    

    if (neutronOut.find("Created a new subnet") != -1):
      neutronOut = neutronOut.splitlines()
      subnetIDS.append([x for x in neutronOut if " id " in x][0].split("|")[2].strip())  #Extract the subnet id from the returned string and add to array
    else:
      subnetIDS.append("ERROR (see logs)- Couldn't create " + reserveResource['ID'] + " @ " + reserveResource['Attributes']['AddressRange'])  #FIX ME - Waht should I do if failure
      logger.error(neutronErr)

    subnetIDS = {"Reservations": subnetIDS}
    
    response.set_header('Content-Type', 'application/json')
    response.set_header('Accept', '*/*')
    response.set_header('Allow', 'GET, HEAD')
    
    logger.info("Completed")
    return subnetIDS


  except Exception.message,e:
    print e
    error = "reserveResources Attempting to read non-existent key, please check payload"
    logger.error(error)
    response.status = 400
    return error

################################## API Stuff - End ####################################
################################## Lib Stuff - Start ##################################

def disassociateFloatingIP(floatingIPID):
  logger.info("Called")
  neutronIn = ["neutron", "floatingip-disassociate", floatingIPID]
  process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  neutronOut, neutronErr = process.communicate()
  
  logger.info("Completed")
  return (neutronOut, neutronErr)

def deleteSubnet(subnetID):
  logger.info("Called")
  neutronIn = ["neutron", "subnet-delete", subnetID]
  process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  neutronOut, neutronErr = process.communicate()
  
  logger.info("Completed")
  return (neutronOut, neutronErr)

def getNeutronFIPEntries():
  logger.info("Called")
  neutronFIPEntries = []
  
  neutronIn = ["neutron", "floatingip-list"]
  process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  neutronOut, neutronErr = process.communicate()
  
  neutronOut = neutronOut.splitlines()[3:-1]
  for neutronEntry in neutronOut:
    entry = {}
    entry["ID"] = neutronEntry.split("|")[1].strip()
    entry["fixedIP"] = neutronEntry.split("|")[2].strip()
    entry["floatingIP"] = neutronEntry.split("|")[3].strip()
    entry["portID"] = neutronEntry.split("|")[4].strip()
    neutronFIPEntries.append(entry)
  
  logger.info("Completed")
  return neutronFIPEntries


def getAvailableFloatingIPs():
  logger.info("Called")
  availableFloatingIPs = []

  neutronFIPEntries = getNeutronFIPEntries()
  for neutronEntry in neutronFIPEntries:
    if neutronEntry["fixedIP"] == "":
      availableFloatingIPs.append(neutronEntry["floatingIP"])
  
  logger.info("Completed")
  return availableFloatingIPs

def getAvailableFloatingIPIDs():
  logger.info("Called")
  availableFloatingIPIDs = []

  neutronFIPEntries = getNeutronFIPEntries()
  for neutronEntry in neutronFIPEntries:
    if neutronEntry["fixedIP"] != "":
      availableFloatingIPIDs.append(neutronEntry["ID"])
  
  logger.info("Completed")
  return availableFloatingIPIDs

def getAvailableSubnets():
  logger.info("Called")
  neutronSubnetsEntries = []
  
  neutronIn = ["neutron", "subnet-list"]
  process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  neutronOut, neutronErr = process.communicate()
  
  neutronOut = neutronOut.splitlines()[3:-1]
  for neutronEntry in neutronOut:
    entry = {}
    entry["ID"] = neutronEntry.split("|")[1].strip()
    entry["name"] = neutronEntry.split("|")[2].strip()
    entry["cidr"] = neutronEntry.split("|")[3].strip()
    #entry["allocationPools"] = neutronEntry.split("|")[4].strip()
    #cidr = neutronEntry.split("|")[3].strip()
    neutronSubnetsEntries.append(entry)
  
  logger.info("Completed")
  return neutronSubnetsEntries

def getAvailableSubnetsIDs():
  logger.info("Called")
  neutronSubnetsEntriesID = []
  
  neutronIn = ["neutron", "subnet-list"]
  process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  neutronOut, neutronErr = process.communicate()
  
  neutronOut = neutronOut.splitlines()[3:-1]
  for neutronEntry in neutronOut:
    if "HARNESS" in neutronEntry.split("|")[2].strip():
      #entry = {}
      #entry["ID"] = neutronEntry.split("|")[1].strip()
      #entry["name"] = neutronEntry.split("|")[2].strip()
      #entry["cidr"] = neutronEntry.split("|")[3].strip()
      #entry["allocationPools"] = neutronEntry.split("|")[4].strip()
      #cidr = neutronEntry.split("|")[3].strip()
      ID = neutronEntry.split("|")[1].strip()
      neutronSubnetsEntriesID.append(ID)
  
  logger.info("Completed")
  return neutronSubnetsEntriesID

def getFIPEntryFromID(entryID):
  logger.info("Called")
  neutronEntries = getNeutronFIPEntries()
  
  for neutronEntry in neutronEntries:
    if neutronEntry["ID"] == entryID:
      logger.info("Completed")
      return neutronEntry
  
  logger.error("Unable to find matching entry for " + entryID)
  return False #If no matching entry found

def getSubnetEntryFromID(entryID):
  logger.info("Called")
  neutronEntries = getAvailableSubnets()
  
  for neutronEntry in neutronEntries:
    if neutronEntry["ID"] == entryID:
      logger.info("Completed")
      return neutronEntry
  
  logger.error("Unable to find matching entry for " + entryID)
  return False #If no matching entry found

def getIDFromFloatingIP(floatingIP):
  logger.info("Called")
  neutronEntries = getNeutronFIPEntries()
  
  for neutronEntry in neutronEntries:
    if neutronEntry["floatingIP"] == floatingIP:
      logger.info("Completed")
      return neutronEntry["ID"]
  
  logger.error("Unable to find matching entry for " + floatingIP)
  return False #If no matching entry found


def getifip(ifn):
  import fcntl, struct
  
  sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(sck.fileno(), 0x8915, struct.pack('256s', ifn[:15]))[20:24])


def startAPI(IP_ADDR, PORT_ADDR):
  # check if irm already running
  command = "ps -fe | grep irm-neutron.py | grep python | grep -v grep"
  proccount = subprocess.check_output(command, shell = True).count('\n')
  proc = subprocess.check_output(command, shell = True)
  if proccount > 1:
      print "---Check if irm is already running. Connection error---"
      sys.exit(0)
  else:
      print"IRM API IP address:", IP_ADDR
      API_HOST=run(host = IP_ADDR, port = PORT_ADDR)
  return IP_ADDR


if __name__ == '__main__':
  main()
  

