Elasticsearch Security Privileges
*********************************

While ElastAlert 2 will just work out-of-the-box for unsecured Elasticsearch, it will need a user with a certain set of permissions to work on secure Elasticseach that allow it to read the documents, check the cluster status etc.

SearchGuard Permissions
=======================

The permissions in Elasticsearch are specific to the plugin being used for RBAC. However, the permissions mentioned here can be mapped easily to different plugins other than Searchguard.

Details about SearchGuard Action Groups: https://docs.search-guard.com/latest/action-groups


Writeback Permissions
---------------------------

For the global config (which writes to the writeback index), you would need to give all permissions on the writeback indices.
In addition, some permissions related to Cluster Monitor Access are required.

``Cluster Permissions``: CLUSTER_MONITOR, indices:data/read/scroll*

``Index Permissions`` (Over Writeback Indices): INDICES_ALL


Per Rule Permissions
--------------------------

For per rule Elasticsearch config, you would need at least the read permissions on the index you want to query.
Detailed SearchGuard Permissions:

``Cluster Permissions``: CLUSTER_COMPOSITE_OPS_RO

``Index Permissions`` (Over the index the rule is querying on): READ, indices:data/read/scroll*


