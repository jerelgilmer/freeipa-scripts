#!/usr/bin/python
'''
 2016 - March - 2
 Author: Jerel Gilmer
'''

import os
import sys
import ldap

def print_usage():
 print "Usage: server-access-report.py <hostname>"
 print "This script generates the list of allowed users for each service defined in applicable HBAC rules.\n"
 print "<hostname> - System hostname; This can be the short name\n"
 print "For report of all systems, use \'.\'\n"
 print "Make sure to set the below variables in the script:"
 print "\tDOMAIN: Domain component"
 print "\tLDAP_SERVER: LDAP server to be queried"
 print "\tLDAP_USER: LDAP user to query server; preferable a read-only account" 
 print "\tLDAP_PW: LDAP user's password\n"
 sys.exit(1)

try:
 server = str(sys.argv[1])
except:
 print_usage()

## LDAP Connection Info and bind to the LDAP server
## Uncomment and set these variables to the appropriate values
## Below are examples 
#DOMAIN = "dc=sub,dc=example,dc=com"
#LDAP_SERVER = "ldap://ipaserver1.sub.example.com"
#LDAP_USER = "uid=user1,cn=users,cn=compat," + DOMAIN
#LDAP_PW = "Password123"

try:
 DOMAIN 
 LDAP_SERVER
 LDAP_USER 
 LDAP_PW
except:
 print_usage()

l = ldap.initialize(LDAP_SERVER)

l.simple_bind_s(LDAP_USER,LDAP_PW)

## LDAP Search Variables
## Base DN for LDAP Searches
baseComputerDN = "cn=computers,cn=accounts," + DOMAIN
baseGroupDN =  "cn=groups,cn=accounts," + DOMAIN
baseUserDN = "cn=users,cn=accounts," + DOMAIN
baseHBACDN = "cn=hbac," + DOMAIN
baseHBACServicesDN = "cn=hbacservices,cn=hbac," + DOMAIN
baseHBACServiceGroupsDN = "cn=hbacservicegroups,cn=hbac," + DOMAIN

## Default LDAP SCOPE
scope = ldap.SCOPE_SUBTREE

## Filter for LDAP Searches
compFilter = "(&(objectclass=ipahost)(fqdn=*" + server + "*))"
hbacFilter = "(objectclass=ipahbacrule)"
userFilter = "(objectclass=person)"
groupFilter = "(objectclass=ipausergroup)"
hbacServiceFilter = "(objectclass=ipahbacservice)"
hbacServiceGroupsFilter = "(objectclass=ipahbacservicegroup)"

## Attributes from LDAP Searches
compAttributes =  ['memberOf', 'fqdn']
hbacAttributes = ['memberUser', 'memberService', 'serviceCategory']
userAttributes = ['uid']
groupAttributes = ['member']
hbacServiceAttributes = ['cn' , 'ipaUniqueID']
hbacServiceGroupsAttributes = ['cn' , 'member']

## Perform LDAP searches and store results into array
ALL_HOSTS = l.search_s(baseComputerDN, scope, compFilter, compAttributes)

ALL_USERS = l.search_s(baseUserDN, scope, userFilter, userAttributes)

ALL_GROUPS = l.search_s(baseGroupDN, scope, groupFilter, groupAttributes)

ALL_HBACRULES = l.search_s(baseHBACDN, scope, hbacFilter, hbacAttributes)

ALL_HBACSERVICES = l.search_s(baseHBACServicesDN, scope, hbacServiceFilter, hbacServiceAttributes)

ALL_HBACSERVICEGROUPS = l.search_s(baseHBACServiceGroupsDN, scope, hbacServiceGroupsFilter, hbacServiceGroupsAttributes)

# HBAC rules that apply to all servers
hbacAllServersFilter = "(&(objectclass=ipahbacrule)(hostCategory=all))"
HBACRULE_ALL_SERVERS = l.search_s(baseHBACDN, scope, hbacAllServersFilter, hbacAttributes)

ALL_HOSTS.sort()

def findUID(user):
 uid = filter(lambda x: user in x, ALL_USERS)
 return uid[0][1]['uid'][0]

def findGroupMembers(groupname):
 if "cn=groups,cn" not in groupname:
  pass
 group = filter(lambda x: groupname in x, ALL_GROUPS)
 try:
  groupmembers = group[0][1]['member']
 except: 
  groupmembers = ""
 for user in groupmembers:
  if "cn=groups,cn" in user:
   for i in findGroupMembers(user):
    yield i
  else:
   yield (findUID(user))
  
def findServiceName(service_name):
 s = filter(lambda x: service_name in x, ALL_HBACSERVICES)
 return s[0][1]['cn'][0]

def findServiceGroupMembers(service_group):
 allServices = []
 serviceGroup = filter(lambda x: service_group in x, ALL_HBACSERVICEGROUPS)
 serviceGroupMembers = serviceGroup[0][1]['member']
 for i in serviceGroupMembers:
  allServices.append(findServiceName(i))
 formattedAllServices = ', '.join(allServices)
 return formattedAllServices

def accessToAllSystems():
 allSystemsHBACRules = {} 

 for hbacname in HBACRULE_ALL_SERVERS:
  hbacrule = filter(lambda x: hbacname[0] in x, ALL_HBACRULES)
  
  for hbacuser in hbacrule:
   services = []
   allowedUsers = []
   users = []
   groups = []

   try:
    users = filter(lambda x: "cn=users,cn" in x, hbacuser[1]['memberUser'])
   except:
    users = []

   try:
    groups = filter(lambda x: "cn=groups,cn" in x, hbacuser[1]['memberUser'])
   except:
    groups = []

   try:
    hbacservice = hbacuser[1]['memberService']
    for i in hbacservice:
     if "hbacservicegroups,cn" in i:
      services.append(findServiceGroupMembers(i))
     else:
      services.append(findServiceName(i))
   except:
    try:
     services = hbacuser[1]['serviceCategory'][0]
    except:
     services = ['None']

   for i in users:
    allowedUsers.append(findUID(i))

   for i in groups:
    allowedUsers += (findGroupMembers(i))
 
  allSystemsHBACRules[hbacrule[0][0]] = {'services': services, 'allowedUsers': allowedUsers}

 return allSystemsHBACRules

def mergeD(results,services):
 for k in results:
  if services == results[k]['services']:
   return "MATCH!!", k

def nestedL(l):
 if isinstance(l, str):
  yield l
 for k in l:
  if isinstance(k, list):
   for i in k:
    yield i
  if isinstance(k, str):
   yield k

def main():
 for entry in ALL_HOSTS:
  systemWide = {}
  HBACAllowedList = {}
  results = {}
  x = 1

  fqdn = entry[1]['fqdn'][0]
 
  print "HOSTNAME = ", fqdn
  try:
   membership = filter(lambda x: "hbac,dc" in x, entry[1]['memberOf'])
  except:
   membership = []

  for hbacname in membership:
   hbacrule = filter(lambda x: hbacname in x, ALL_HBACRULES)
   for hbacuser in hbacrule:
    allowedUsers = []
    allowedUsersLst = []
    users = []
    groups = []
    services = []
    try:
     hbacservice = hbacuser[1]['memberService']
     for i in hbacservice:
      if "hbacservicegroups,cn" in i:
       services.append(findServiceGroupMembers(i))
      else:   
       services.append(findServiceName(i))
    except:
     try:
      services = hbacuser[1]['serviceCategory'][0]
     except:
      services = [] 
    try:
     users = filter(lambda x: "cn=users,cn" in x, hbacuser[1]['memberUser'])
    except: 
     users = []
 
    try:
     groups = filter(lambda x: "cn=groups,cn" in x, hbacuser[1]['memberUser'])
    except:
     groups = []
   
    for i in users:
     allowedUsers.append(findUID(i))

    for i in groups:
     allowedUsers += findGroupMembers(i)
 
    HBACAllowedList[hbacrule[0][0]] = {'services': services, 'allowedUsers': allowedUsers}

  systemWide = accessToAllSystems()
  HBACAllowedList.update(accessToAllSystems())

  for key, value in HBACAllowedList.iteritems():
  
   if isinstance(value['services'], list):
    services = ', '.join(value['services'])
   else:
    services = value['services']

   allowedUsers = value['allowedUsers']

   try:
    mark, key = mergeD(results,services)
   except:
    mark, key = (None, None)

   if mark == "MATCH!!":
    results[key]['allowedUsers'].append(allowedUsers)
   else:
    results[x] = {'services': services, 'allowedUsers': allowedUsers}
    x = x + 1

  for i in results:
   results_services = results[i]['services']
 
   results_allowedUsers = list(nestedL(results[i]['allowedUsers']))
   results_allowedUsersSet = set(results_allowedUsers)
   results_allowedUsersLst = list(results_allowedUsersSet)
   results_allowedUsersLst.sort()
   formatted_allowedUsers = ' '.join(results_allowedUsersLst)

   if not results_services:
    results_services = 'empty'
   if not formatted_allowedUsers:
    formatted_allowedUsers = 'empty'
   print "SERVICES = ", results_services
   print "ALLOWED USERS = ", formatted_allowedUsers, "\n"

main()
