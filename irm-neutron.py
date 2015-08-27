#!/usr/bin/env python

import requests, json, subprocess
from bottle import route, run,response,request
import ConfigParser, optparse
import logging
import logging.handlers as handlers
import socket
import sys
import os
from threading import Thread

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
  
  if CONFIG.has_option('main', 'USERNAME'):
     os.environ['OS_USERNAME'] = CONFIG.get('main', 'USERNAME')
     
  if CONFIG.has_option('main', 'TENANT_NAME'):
     os.environ['OS_TENANT_NAME'] = CONFIG.get('main','TENANT_NAME')

  if CONFIG.has_option('main', 'PASSWORD'):
     os.environ['OS_PASSWORD'] = CONFIG.get('main','PASSWORD')

  if CONFIG.has_option('main', 'NOVA_ENDPOINT'):
     os.environ['OS_AUTH_URL'] = "http://%s/v2.0" % CONFIG.get('main','NOVA_ENDPOINT')
  
  global NET_ID   
  if CONFIG.has_option('network', 'NET_ID'):
     NET_ID = CONFIG.get('network','NET_ID')
  else:
     NET_ID = "demo-net"
     
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
      availableSubnets = [ {"cidr": x["cidr"], "name": x["name"].replace("HARNESS-", "")} \
         for x in getAvailableSubnets() if ("HARNESS-" in x['name']) ] 
      
      public_ips = {"Type" : "PublicIP", "Attributes" : { "IP-Pool": availableFloatingIPs}}
      subnets = {"Type" : "Subnet", "Attributes" : { "AvailableSubnets": availableSubnets}}
      
      r = {"Resources" : {"ID-P0": public_ips, "ID-S0": subnets }}
       
      result = json.dumps({"result": r})

  except Exception as e:
     response.status = 400
     error = {"message" : e.message, "code" : response.status}
     logger.error(error)
     return json.dumps({"error": error})

  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')

  logger.info("Completed")
  return result


@route('/getAllocSpec/', method = 'GET')
@route('/getAllocSpec', method = 'GET')
def getAllocSpec():
  logger.info("Called")
  
  try:
     PublicIP = {"IP": { "Description": "IP address", "DataType": "string"}, "VM": { "Description": "VM to apply the public IP (VM reservationID)", "DataType": "string" }}
     Subnet = {"AddressRange" : { "Description" : "Address range (e.g. 192.163.0.0/24)", "DataType": "string" }, "Name": { "Description": "Name of the subnet",  "DataType": "string" }}
  
     r = {"Types" : {"PublicIP": PublicIP, "Subnet": Subnet}}
     result = json.dumps({"result": r})
  
  except Exception as e:
     response.status = 400
     error = {"message" : e.message, "code" : response.status}
     logger.error(error)
     return json.dumps({"error": error})

  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')

  logger.info("Completed")
  return result


#Expects three lists (Resource, Allocation and Release) containing the ID's of neutron entries
@route('/calculateCapacity/', method='POST')
@route('/calculateCapacity', method='POST')
def computeCapacity():
  logger.info("Called")  
  try:
    req = json.load(request.body)
    
    resource = req.get("Resource")
    
    if resource.get("Type") == "PublicIP":
       if "Allocation" not in req:
          allocations = []
       else :
          allocations = req.get("Allocation")
       
       if "Release" not in req:
          releases = []
       else:
          releases = req.get("Release")

       for release in releases:
          resource["Attributes"]["IP-Pool"].append(release["Attributes"]["IP"])

       for allocation in allocations: 
          if allocation["Attributes"]["IP"] in resource["Attributes"]["IP-Pool"]:
             resource["Attributes"]["IP-Pool"].remove(allocation["Attributes"]["IP"])
          else:
             return json.dumps({"result": {}}) 
             
    elif resource.get("Type") == "Subnet":
      if "Allocation" not in req:
          allocations = []
      else:
          allocations = req.get("Allocation")             
       
      if "Release" not in req:
          releases = []
      else:
          releases = req.get("Release")
       
      for release in releases:
          subnet_names = [(i["name"], i["cidr"]) for i in resource["Attributes"]["AvailableSubnets"]] 
          if (release["Attributes"]["Name"],release["Attributes"]["AddressRange"])  in subnet_names: 
             
             resource["Attributes"]["AvailableSubnets"] = filter(lambda x: x["name"] != \
                               release["Attributes"]["Name"] or x["cidr"] != release["Attributes"]["AddressRange"], \
                                   resource["Attributes"]["AvailableSubnets"])
          else:
             return json.dumps({"result": {}})     
      
      for allocation in allocations:
          subnet_names = [i["name"] for i in resource["Attributes"]["AvailableSubnets"]]
          subnet_cidr =  [i["cidr"] for i in resource["Attributes"]["AvailableSubnets"]]
          if (allocation["Attributes"]["Name"] not in subnet_names) and \
             (allocation["Attributes"]["AddressRange"] not in subnet_cidr):
             
             resource["Attributes"]["AvailableSubnets"].append( { "cidr": allocation["Attributes"]["AddressRange"], \
                                                                  "name": allocation["Attributes"]["Name"] } )
          else:
             return json.dumps({"result": {}})              
              
  except Exception as e:
    response.status = 400
    error = {"message" : e.message, "code" : response.status}
    logger.error(error)
    return json.dumps({"error": error})    

  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')

  logger.info("Completed")
  
  return json.dumps({"result": {"Resource": resource}})


#Expects a list of dictionaries containing "VirtualMachine" (ID/name of VM) and "floatingIP" (floatingIP to assign) 
@route('/createReservation/', method='POST')
@route('/createReservation', method='POST')
def createReservation():
  logger.info("Called")
  
  global NET_ID

  try:
    req = json.load(request.body)
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

      if typeN == "PublicIP":
      
        if "VM" not in allocation["Attributes"]:
           raise Exception("VM missing in allocation request attributes!")
        if "IP" not in allocation["Attributes"]:
           raise Exception("IP missing in allocation request attributes!")        
      
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
        if "Name" not in allocation["Attributes"]:
           raise Exception("Name missing in allocation request attributes!")
        if "AddressRange" not in allocation["Attributes"]:
           raise Exception("AddressRange missing in allocation request attributes!")          
            
        name = "HARNESS-"+allocation.get("Attributes").get("Name")
        cidr = allocation.get("Attributes").get("AddressRange")
        
        print "cidr",cidr
                
        if len([x for x in availableSubnets if x['cidr'] == cidr or x['name'] == name]) == 0: 
          neutronIn = ["neutron", "subnet-create", NET_ID, "--name", name, cidr]
          process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          neutronOut, neutronErr = process.communicate()

          if (neutronOut.find("Created a new subnet") != -1):
            neutronOut = neutronOut.splitlines()
            reservations.append([x for x in neutronOut if " id " in x][0].split("|")[2].strip())  #Extract the subnet id from the returned string and add to array
          else:
            #reservations.append("ERROR (see logs)- Couldn't create " + allocation.get("ID") + " @ " + allocation.get("Attributes").get("AddressRange"))  #FIX ME - Waht should I do if failure
            logger.error(neutronErr)
            raise Exception(neutronErr)
        else:
          raise Exception("cidr %s or name %s already used" % \
                (cidr, allocation.get("Attributes").get("Name")))

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
  except Exception as e:
     response.status = 400
     error = {"message" : e.message, "code" : response.status}
     logger.error(error)
     return json.dumps({"error": error})


  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')
    
  logger.info("Completed")
  return json.dumps({"result": {"ReservationID": reservations}})


@route('/checkReservation/', method='POST')
@route('/checkReservation', method='POST')
def checkReservation():
  logger.info("Called")

  try:
    req = json.load(request.body)

    reservationIDs = req.get("ReservationID")
    reservations = {}

    for reservationID in reservationIDs:
      reservation = {}
      neutronEntry = getFIPEntryFromID(reservationID)

      if neutronEntry:
        reservation["Ready"] = "False"
        #if (neutronEntry != False):
        if (neutronEntry["fixedIP"] != ""):
          reservation["Address"] = [neutronEntry["floatingIP"]]
          reservation["Ready"] = "True"
        #else:
        #  reservation["ERROR"] = "No matching reservation for " + reservationID
      else:
        neutronEntry = getSubnetEntryFromID(reservationID)
        if neutronEntry:
          #reservation["Ready"] = False
          #if (neutronEntry != False):
          #if (neutronEntry["fixedIP"] != ""):
          name = neutronEntry["name"]
          if "HARNESS-" in name:
             name = name.replace("HARNESS-", "")
          reservation["Address"] = [name]
          reservation["Ready"] = "True"
        else:
          raise Exception("No matching reservation for " + reservationID)
        
      reservations[reservationID] = reservation
      
    reservations = {"Instances" : reservations}
  except Exception as e:
     response.status = 400
     error = {"message" : e.message, "code" : response.status}
     logger.error(error)
     return json.dumps({"error": error})
     
  response.set_header('Content-Type', 'application/json')
  response.set_header('Accept', '*/*')
  response.set_header('Allow', 'GET, HEAD')

  logger.info("Completed")
    
  return json.dumps({"result": reservations})

@route('/releaseReservation/', method='DELETE')
@route('/releaseReservation', method='DELETE')
def releaseReservation():
  logger.info("Called")

  try:
    #print ID
    req = json.load(request.body)
    reservationIDs = req.get("ReservationID")
    availableFloatingIPIDs = getAvailableFloatingIPIDs()
    availableSubnetsIDs = getAvailableSubnetsIDs()
    
    for reservationID in reservationIDs:
      if reservationID in availableSubnetsIDs:
        deleteSubnet(reservationID)
      elif reservationID in availableFloatingIPIDs:
       disassociateFloatingIP(reservationID)
 
  except Exception as e:
     response.status = 400
     error = {"message" : e.message, "code" : response.status}
     logger.error(error)
     return json.dumps({"error": error})
     
  logger.info("Completed")
    
  return json.dumps({"result": {}})
 
@route('/releaseAllReservations/', method='DELETE')
@route('/releaseAllReservations', method='DELETE')
def releaseAllReservations():
  logger.info("Called")

  try:
     neutronFIPEntries = getNeutronHARNESSactiveFIPEntries()
     neutronSubnetsEntries = getAvailableSubnets()
     for subnet in neutronSubnetsEntries:
        if "HARNESS" in subnet.get('name'):
          deleteSubnet(subnet.get('ID'))

     for neutronEntry in neutronFIPEntries:
        if neutronEntry["fixedIP"] != "":
           disassociateFloatingIP(neutronEntry["ID"])
  
     logger.info("Completed")
  except Exception as e:
     response.status = 400
     error = {"message" : e.message, "code" : response.status}
     logger.error(error)
     return json.dumps({"error": error})   
   
  return json.dumps({"result":{}})

############################## reserveResources method from irm-net for creating subnets ##############################

#@route('/reserveResources/', method='POST')
#@route('/reserveResources', method='POST')
#def reserveResources():
#  logger.info("Called")
#  import subprocess
#  
#  global NET_ID
#  try:
#    print ID
#    req = json.load(request.body)
#  except ValueError:
#    response.status = 400
#    error = "reserveResources was not supplied with a payload, please enter desired payload"
#    logger.error(error)
#    return error

#  try:
#    reserveResource = req['Allocation']
#    print reserveResource
#    print reserveResource['ID']
#    print reserveResource['Attributes']['AddressRange']

#    subnetIDS = []
#    for reserveResource in reserveResources:
#    neutronIn = ["neutron", "subnet-create", NET_ID, "--name", reserveResource['ID'], reserveResource['Attributes']['AddressRange']]
#    process = subprocess.Popen(neutronIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#    neutronOut, neutronErr = process.communicate()


#    
#     ##FOR TESTING - REMOVE! ##
#     neutronOut = "Created a new subnet:\n"
#     neutronOut += "+------------------+--------------------------------------------------+\n"
#     neutronOut += "| Field            | Value                                            |\n"
#     neutronOut += "+------------------+--------------------------------------------------+\n"
#     neutronOut += "| allocation_pools | {\"start\": \"192.168.2.2\", \"end\": \"192.168.2.254\l\"} |\n"
#     neutronOut += "| cidr             | 192.168.2.0/24                                   |\n"
#     neutronOut += "| dns_nameservers  |                                                  |\n"
#     neutronOut += "| enable_dhcp      | True                                             |\n"
#     neutronOut += "| gateway_ip       | 192.168.2.1                                      |\n"
#     neutronOut += "| host_routes      |                                                  |\n"
#     neutronOut += "| id               | 15a09f6c-87a5-4d14-b2cf-03d97cd4b456             |\n"
#     neutronOut += "| ip_version       | 4                                                |\n"
#     neutronOut += "| name             | subnet1                                          |\n"
#     neutronOut += "| network_id       | 2d627131-c841-4e3a-ace6-f2dd75773b6d             |\n"
#     neutronOut += "| tenant_id        | 3671f46ec35e4bbca6ef92ab7975e463                 |\n"
#     neutronOut +=  "+------------------+--------------------------------------------------+"
#     ##FOR TESTING FIX ME - REMOVE! ##
#    

#    if (neutronOut.find("Created a new subnet") != -1):
#      neutronOut = neutronOut.splitlines()
#      subnetIDS.append([x for x in neutronOut if " id " in x][0].split("|")[2].strip())  Extract the subnet id from the returned string and add to array
#    else:
#      subnetIDS.append("ERROR (see logs)- Couldn't create " + reserveResource['ID'] + " @ " + reserveResource['Attributes']['AddressRange'])  FIX ME - Waht should I do if failure
#      logger.error(neutronErr)

#    subnetIDS = {"Reservations": subnetIDS}
#    
#    response.set_header('Content-Type', 'application/json')
#    response.set_header('Accept', '*/*')
#    response.set_header('Allow', 'GET, HEAD')
#    
#    logger.info("Completed")
#    return subnetIDS


#  except Exception.message,e:
#    print e
#    error = "reserveResources Attempting to read non-existent key, please check payload"
#    logger.error(error)
#    response.status = 400
#    return error

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

def getNeutronHARNESSactiveFIPEntries():
  logger.info("Called")
  neutronFIPEntries = []
  novaHARNESSEntries = []
  neutronHARNESSactiveFIPEntries = []

  neutronFIPEntries = getNeutronFIPEntries()
  novaHARNESSEntries = getNovaHARNESSlist()

  for neutronEntry in neutronFIPEntries:
    fIP = neutronEntry['floatingIP']
    if len(novaHARNESSEntries) > 0 and fIP in novaHARNESSEntries[0]['NET']:
      neutronHARNESSactiveFIPEntries.append(neutronEntry)
  
  logger.info("Completed")
  return neutronHARNESSactiveFIPEntries

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

def getNovaHARNESSlist():
  logger.info("Called")
  novaHARNESSEntries = []
  
  novaIn = ["nova", "list"]
  process = subprocess.Popen(novaIn, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  novaOut, novaErr = process.communicate()
  
  novaOut = novaOut.splitlines()[3:-1]
  for novaEntry in novaOut:
    entry = {}
    entry["ID"] = novaEntry.split("|")[1].strip()
    entry["Name"] = novaEntry.split("|")[2].strip()
    entry["NET"] = novaEntry.split("|")[6].strip()
    if "HARNESS" in entry["Name"]:
      novaHARNESSEntries.append(entry)
  
  logger.info("Completed")
  return novaHARNESSEntries

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

def registerIRM():
    logger.info("Called")
    logger.info( "ip:%s , port:%s, crs: %s" % (IP_ADDR, PORT_ADDR, CONFIG.get('CRS', 'CRS_URL')))
    headers = {'content-type': 'application/json'}
    try:
       data = json.dumps(\
       {\
       #"Address":IP_ADDR,\
       "Port":PORT_ADDR,\
       "Name":"IRM-NEUTRON"\
       })
    except AttributeError:
        logger.error("Failed to json.dumps into data")
   
    # add here a check if that flavor name exists already and in that case return the correspondent ID
    # without trying to create a new one as it will fail
    r = requests.post(CONFIG.get('CRS', 'CRS_URL')+'/registerManager', data, headers=headers)
    logger.info("Completed!")


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
      if CONFIG.has_option('CRS', 'ACTIVE') and CONFIG.get('CRS', 'ACTIVE') == "on":
            Thread(target=registerIRM).start()
            print 'Registration with CRS done'
            logger.info("Registration with CRS done")      
      API_HOST=run(host = IP_ADDR, port = PORT_ADDR)
  return IP_ADDR

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


if __name__ == '__main__':
  main()
  

