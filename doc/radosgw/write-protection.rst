Bucket Write Protection
=======================

Ceph RGW supports a native bucket-level write-protection feature. This allows cloud admins or service users to mark a bucket as "write protected", ensuring that non-admin end users cannot modify the bucket or its objects, while still being able to read and list them.

This feature is available for both S3 and Swift frontends.

Admin Role Recognition
----------------------

Users identified as "cloud admin" are allowed to modify protected buckets and toggle the protection flag.
Admin roles are defined by the ``rgw_keystone_accepted_admin_roles`` configuration option for Keystone users.
Local RGW users with ``system`` capabilities or specific administrative caps are also treated as admins.

S3 Configuration
----------------

To enable or disable write protection on an S3 bucket, use the **Bucket Tagging** API.

Use the reserved tag key ``rgw:write_protected`` with a value of ``true`` or ``false``.

Example enabling protection:

.. code-block:: xml

   <Tagging>
     <TagSet>
       <Tag>
         <Key>rgw:write_protected</Key>
         <Value>true</Value>
       </Tag>
     </TagSet>
   </Tagging>

Only admin users can set this tag. Attempts by non-admin users will result in ``AccessDenied``.

Swift Configuration
-------------------

For Swift, use the container metadata header ``X-Container-Meta-Write-Restricted``.

To enable protection:

.. code-block:: bash

   curl -i -X POST -H "X-Auth-Token: <token>" -H "X-Container-Meta-Write-Restricted: true" <storage_url>/<container>

To disable protection:

.. code-block:: bash

   curl -i -X POST -H "X-Auth-Token: <token>" -H "X-Remove-Container-Meta-Write-Restricted: x" <storage_url>/<container>

Or set it to ``false``.

Behavior
--------

When a bucket is write-protected:

*   **Allowed**: GET/HEAD operations on bucket and objects, List operations.
*   **Denied (for non-admins)**: PUT, POST, DELETE operations on bucket and objects.

Admin users can still perform write operations on protected buckets.
