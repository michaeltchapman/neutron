#!/bin/bash

# Default values
# --------------
adminUser="quantum"
adminRole="admin"
l3AdminTenant="L3AdminTenant"


echo -n "Checking if $l3AdminTenant tenant exists ..."
tenantId=`keystone tenant-get $l3AdminTenant 2>&1 | awk '/No tenant|id/ { if ($1 == "No") print "No"; else print $4; }'`

if [ "$tenantId" == "No" ]; then
   echo " No, it does not. Creating it."
   tenantId=`keystone tenant-create --name $l3AdminTenant --description "Owner of CSR1kv VMs" | awk '/id/ { print $4; }'`
else
   echo " Yes, it does."
fi


echo -n "Checking if $adminUser user has admin privileges in $l3AdminTenant tenant ..."
isAdmin=`keystone --os-username $adminUser --os-tenant-name $l3AdminTenant user-role-list 2>&1 | awk 'BEGIN { res="No" } { if ($4 == "admin") res="Yes"; } END { print res; }'`

if [ "$isAdmin" == "No" ]; then
   echo " No, it does not. Giving it admin rights."
   admUserId=`keystone user-get $adminUser | awk '{ if ($2 == "id") print $4 }'`
   admRoleId=`keystone role-get $adminRole | awk '{ if ($2 == "id") print $4 }'`
   keystone user-role-add --os-username $adminUser --os-tenant-name --user-id $admUserId --role-id $admRoleId --tenant-id $tenantId
else
   echo " Yes, it has."
fi

