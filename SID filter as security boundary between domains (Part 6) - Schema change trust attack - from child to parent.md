Originally published on https://blog.improsec.com April 7th 2022.
https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent
_Authors: Jonas Bülow Knudsen, Martin Sohn Christensen, Tobias Thorbjørn Munch Torp


This is part six of a seven part series. Check out [part 1 Kerberos authentication explained](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) for links to the others.

In [part five](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent) of this series, we explored how the replication of Configuration naming context (NC) allows for the GoldenGMSA trust attack. Exploring what else is stored in Configuration we find the AD Schema, and this post explores how this schema replication allows a child domain to modify the schema and thereby compromise objects in the parent domain, just as if you were a Schema Admin (a group only existing in the root/parent domain of AD).

# Content

- Active Directory Schema attack theory
    
- Schema change trust attack – from child to parent
    
- Mitigation and detection
    
- Part 6 conclusion
    

# Active Directory Schema attack theory

According to Microsoft: “The Microsoft Active Directory schema contains formal definitions of every object class that can be created in an Active Directory forest. The schema also contains formal definitions of every attribute that can exist in an Active Directory object”.

One of these attributes is the [defaultSecurityDescriptor](https://docs.microsoft.com/en-us/windows/win32/ad/default-security-descriptor) which “is used to provide default protection on the object if there is no security descriptor specified during the creation of the object”.

Anyone with rights to modify the defaultSecurityDescriptor schema attribute will therefore be able to define ACLs on any newly created objects in the parent domain. [Abusing the Schema Admins privileges are commonly known](https://cube0x0.github.io/Pocing-Beyond-DA/), and possible attacks depend on the object affected. Some examples of these backdoors on different objects are:

- Groups
    
    - Add members
        
- Users
    
    - Reset password
        
    - Write SPN, then perform Kerberoasting
        
    - Disable Kerberos preauthentication, then perform AS-REP Roasting
        
- Group Policy Objects
    
    - Add user logon script and link to Domain Admin OU
        
    - Add user to Administrators via Restricted Groups and link to Domain Controllers container
        

Other than changing the defaultSecurityDescriptor, it is also possible to remove the [confidential flag](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential) of attributes, [more information is available here](https://zer1t0.gitlab.io/posts/attacking_ad/#properties).

# Schema change trust attack – from child to parent

Looking at the Schema container, stored in the Configuration NC, we find that the child domain is not granted rights, but SYSTEM is granted ‘Full control’:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/0ee12389-dd6b-44d9-b3cf-aabf79ec22e5/Picture14.png)

As seen in the previous posts, the Configuration NC is replicated to child domains, which means we can modify the schema.

As shown in the previous posts, ADSIEdit.msc is run with SYSTEM privileges on a child DC. With SYSTEM privileges it would seem possible to modify Configuration Schema objects in the child domain and wait for replication to the parent domain, but modifying a defaultSecurityDescriptor attribute returns the error:

Operation failed. Error code: 0x202b
A referral was returned from the server.
0000202B: RefErr: DSID-030A08E3, data 0, 1 access points
    ref 1:
‘9f360445-857a-4815-8f3d-cad43c41272d._msdcs.root.local’

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/f31d61f0-73ff-4bd7-b59b-7e33056d1506/Picture15.png)

Instead, we found it possible to modify the ACL of the Schema container. The right “Write property (defaultSecurityDescriptor)” is granted to the CHILD\Administrator user on the Schema container and inherited to all classSchema objects:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/e8b0d231-0b7f-4998-af42-f0d3ec24908c/Picture17.png)

The right is here seen with ldp.exe:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/8f982a69-2d7d-4480-b4c7-70bada99f5d6/Picture19.png)

The ACL is then replicated to the parent domain, and we can then modify defaultSecurityDescriptor of objects in the parent domain. Next, we identify the original defaultSecurityDescriptor:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/880a495e-64dc-4408-9234-1dca487f620d/Picture20.png)

The original defaultSecurityDescriptor is appended with an ACE string granting ‘GenericAll’, to the SID of the user CHILD\child-user, here we also give the ‘Server’ argument pointing to the parent domain root.local:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/d8895d25-cc05-4cac-bbcf-aed541400d15/Picture23.png)

Inspecting the User schema class attribute from the root domain, we see the change was successful:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/705c2f6e-4a30-4191-ae11-f4d4466d76a3/Picture24.png)

Any new user objects in the parent domain will now have a DACL granting CHILD\child-user the right Full Control:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/8d2c658c-b66a-4686-9ac4-deb0fa7694e3/Picture25.png)

As explained earlier, this attack can do much more than affect new user objects.

# Mitigation and detection

We believe no mitigations exist against this attack because the mitigation would be to prevent replication of Schema in the Configuration NC which we do not believe is possible.

We did not find a way for a parent domain to detect modification of the Schema container ACL. We believe this is because replication is not triggering the SACL. However, detection of this attack may be detected by explicitly setting SACLs on all Schema objects to detect writes to attributes that can be used for compromises, such as ‘defaultSecurityDescriptor’ and ‘searchFlags’.

# Part 6 conclusion

In this post, we explained and demonstrated the Schema change trust attack, which allows a child domain to compromise newly created objects in a parent domain. A way of defending against this attack is by using detections.

This is the last post of this series exploring an intra-forest trust attack (within a forest), in [part 7](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted) we explore an inter-forest trust attack (between forests) where a trusted forest can be compromised by a trusting forest.