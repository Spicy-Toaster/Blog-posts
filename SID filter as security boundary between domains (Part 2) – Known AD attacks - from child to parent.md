Originally published on https://blog.improsec.com March 29nd 2022. 
https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent
_Authors: Jonas Bülow Knudsen, Martin Sohn Christensen, Tobias Thorbjørn Munch Torp

This is part two of a seven part series. Check out [part 1 Kerberos authentication explained](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) for links to the others.

This blog post will demonstrate how an attacker with Domain Admin access in a child domain can escalate to Enterprise Admins using known attacks. Various misconfigurations and vulnerabilities also make it possible to accomplish this escalation, the methods covered in this blogpost are all based on Kerberos weaknesses which work in a default AD environment and are rarely prevented.

All three attack methods have been disclosed long ago. The purpose of the blog post is to demonstrate known attacks before we explore prevention of the attacks in part 3 of the blogpost series on SID filtering. Part 1: [Kerberos authentication explained](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) covers the required Kerberos knowledge to understand the underlying mechanisms abused in this blog post, part 1 is therefore recommended to be read first.

# Content

- Demonstration
    
    - Lab setup
        
    - Method #1 Create golden ticket with krbtgt secret key
        
    - Method #2 Create inter-realm golden ticket with trust key
        
    - Method #3 Abuse unconstrained delegation and printer bug
        
- Part 2 conclusion
    

# Demonstration

If you are a member of Domain Admins in a child domain, you can trick the KDC of the root domain to treat you as Enterprise Admins member by abusing Kerberos weaknesses.

The attack can be performed with four different methods. This post will demonstrate methods 1-3.

**1. Create golden ticket with krbtgt secret key**

You can extract the child domain krbtgt’s secret key from a DC, and then create a TGT for the child domain (a golden ticket). If you add the SID of Enterprise Admins to the ExtraSids attribute of the PAC, this SID will be copied to the inter-realm TGT and to the service ticket. When you access any service in the forest and you will be treated as a member of Enterprise Admins.

**2. Create inter-realm golden ticket with trust key**

You can obtain the inter-realm trust keys of the child domain with Domain Admins access. Such a key can be used to craft an inter-realm TGT, where you add the SID of Enterprise Admins to the ExtraSids attribute of the PAC, like the first method. You will then use this ticket to request service tickets, and be treated as Enterprise Admin.

**3. Abuse unconstrained delegation and printer bug**

By tricking a DC from the root domain to login on a compromised child domain server (e.g. using [SpoolSample](https://github.com/leechristensen/SpoolSample)) that has unconstrained delegation enabled, you can obtain a root DC’s TGT and DCSync the krbtgt of the root domain. The krbtgt secret key of the root domain allows you to create a golden ticket as a member of Enterprise Admins.

**4. Edit the SID history of your user**

Microsoft has made it difficult to manually modify the SID history of users. However, Benjamin Delpy has made it [possible with Mimikatz](https://twitter.com/gentilkiwi/status/728367477458145280). Instead of forging a Kerberos ticket with a modified ExtraSids attribute, the Enterprise Admins SID can simply be added to the SID history of a user. It is then included in the ExtraSids of the PAC of the user’s TGT and inter-realm TGT. Unfortunately, this function is [currently not working with Mimikatz](https://github.com/gentilkiwi/mimikatz/issues/348), and we do not know of another tool with this feature, so we skip this one.

## Lab setup

The three methods (1-3) for escalating from Domain Admins are demonstrated from child domain named _CHILD_ (child.root.local) to Enterprise Admins in the root domain _ROOT_ (root.local) which have the default child-parent trust relationship.

The CHILD DC (CHILD-DC-01) and our compromised _child-admin_ user:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/94165477-1146-4e54-a6f0-0b6974658583/image1.png)

The ROOT DC (ROOT-DC-01):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/8e0af859-f076-4374-9def-e4827334731f/image2.png)

WinRM is open on ROOT-DC-01, but when we try to connect with PowerShell Remoting as child-admin, we get access denied as we do not have administrative access to the server:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/93bd107e-bc98-44d0-a111-9b886659d114/image3.png)

## Method #1 Create golden ticket with krbtgt secret key

We will in this method craft a TGT (golden ticket) using the child domain krbtgt secret key with the ExtraSids attribute set to Enterprise Admins SID, which should trick the parent domain to treat us as Enterprise Admins.

First, we dump the krbtgt secret keys with [Mimikatz](https://github.com/gentilkiwi/mimikatz) on CHILD-DC-01:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/5937c346-c867-4229-aa9c-7a35516c239e/image4.png)

> |Argument|Info|
> |---|---|
> |`lsadump::lsa`|Tells Mimikaz to target lsass.exe.|
> |`/inject`|Inject lsass.exe to extract credentials.|
> |`/name:<username>`|Username which the attack will target and extracts secret keys of.|

With the secret key we create a golden ticket using [Rubeus](https://github.com/GhostPack/Rubeus):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/494e93ae-122f-4c53-afe6-0cd24c5f3628/image5.png)

> |Argument|Info|
> |---|---|
> |`golden`|Tells Rubeus to generate a golden ticket|
> |`/user:<username>`|Username in child domain which the TGT will represent|
> |`/id:<user RID>`|RID of the child domain user the ticket is forged to|
> |`/domain:<child domain>`|Child domain DNS name|
> |`/sid:<child domain SID>`|SID of child domain|
> |`/groups:<RIDs>`|RIDs of domain groups from child domain of which the user is a member. Will be set in GroupIds attribute of the PAC. RID 513 is the group Domain Users.|
> |`/sids:<group SIDs>`|SIDs of the groups added to ExtraSids of the PAC. The SID we have added is Enterprise Admins SID from the parent domain.|
> |`/aes256:<krbtgt secret AES256 key>`|Child domain’s krbtgt secret AES256 key to encrypt the ticket.|
> |`/ptt`|Tells Rubeus to inject the TGT into memory.|

We can now verify that we have the golden ticket in memory and that we have PS Remoting access to the root DC as Enterprise Admins:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/33b929b1-9ba5-45a9-94c6-46df777184c8/image6.png)

It worked, and we succeeded in escalating to Enterprise Admins.

Using Mimikatz, we can dump the Kerberos tickets from memory for inspection:

```cpp
sekurlsa::tickets /export
```

Decrypting the tickets using [decryptKerbTicket.py](https://gist.github.com/xan7r/ca99181e3d45ee2042425f4f9181e614) (Rubeus describe command can also be used) for child-admin reveals that the ExtraSids attribute indeed is populated with the Enterprise Admins SID:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/7d6f5673-d41d-4b56-a4b0-459a7b57ad46/image7.png)

## Method #2 Create inter-realm golden ticket with trust key

Again, in this method, we will craft our own ticket with Enterprise Admins in ExtraSids, but this time using the inter-realm trust key instead of the krbtgt secret key, which gives an inter-realm golden ticket.

We dump the inter-realm trust keys using Mimikatz:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/5b707e1e-27fd-4241-b3ed-afa0fddf2452/image8.png)

We use the RC4 key, as that is what MS-KILE will do by default. This AD environment is less than 30 days old, so all RC4 trust keys are identical, in an older environment, we would have used the RC4 key under `[ In ]`. We create the inter-realm golden ticket using Rubeus:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/fcd78574-83bb-4547-b22a-6ba5e6a121e9/image9.png)

> |Argument|Info|
> |---|---|
> |`silver`|Tells Rubeus to generate a Kerberos ticket. The Rubeus [documentation for golden and silver commands](https://github.com/GhostPack/Rubeus#ticket-forgery) explains that the silver command can be used to create service tickets and these more advanced inter-realm TGTs. The golden command is a simpler version of the silver command with fewer arguments only relevant for creating regular golden tickets (TGT).|
> |`/user:<username>`|Username in child domain which the TGT will represent.|
> |`/id:<user RID>`|RID of the child domain user the ticket is forged to.|
> |`/domain:<child domain>`|Child domain DNS name.|
> |`/sid:<child domain SID>`|SID of child domain.|
> |`/groups:<RIDs>`|RIDs of domain groups from child domain of which the user is a member. Will be set in GroupIds attribute of the PAC. RID 513 is the group Domain Users.|
> |`/sids:<SIDs>`|SIDs of the groups added to ExtraSids of the PAC. The SID we have added is Enterprise Admins SID.|
> |`/service:<SPN>`|SPN of the service we want a ticket for i.e. krbtgt/root.local.|
> |`/rc4:<inter-realm RC4 trust key>`|The inter-realm RC4 trust key of the child-parent relationship to encrypt the ticket.|
> |`/nowrap`|Tells Rubeus to print the ticket as base64 without wrapping the text.|

We chose to print the ticket instead of injecting it into memory because MS-KILE will not (for a reason we don’t know) use our inter-realm TGT from memory when we access services. Instead, we use Rubeus to send a TGS-REQ to the ROOT DC with our forged inter-realm TGT:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/5e5e953b-80f9-4ba1-b3f3-e9138afd2232/image10.png)

> |Argument|Info|
> |---|---|
> |`asktgs`|Tells Rubeus to request a service ticket (TGS-REQ).|
> |`/service:<SPN>`|SPN of the service we want a ticket for. We choose HTTP as that is what we need for PS Remoting.|
> |`/dc:<root DC>`|DNS name of root DC.|
> |`/ticket:<inter-realm TGT>`|The forged inter-realm TGT in base64.|
> |`/ptt`|Tells Rubeus to inject the service ticket into memory.|

The forged service ticket is now in memory (ticket #2):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/0b41f24f-59be-4373-a329-5838f78f5447/image11.png)

We can now access the root DC with PS remoting as Enterprise Admins:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/14915843-8cbe-4747-a155-06f055306730/image12.png)

## Method #3 Abuse unconstrained delegation and printer bug

With administrative access to a server hosting a service configured with unconstrained delegation, it is possible to steal the TGT of the users accessing the service, as these TGTs are stored in memory. The TGTs enable you to impersonate the users and request service tickets as them. Therefore, you can compromise the victim by tricking your victim into accessing the service.

Various methods exist for tricking a user or computer to access a service, one of them being [SpoolSample](https://github.com/leechristensen/SpoolSample) which exploits “the printer bug” in the Windows print spooler service, which makes the computer account hosting the print spooler service authenticate to a target chosen by the attacker. SpoolSample sends a _RpcRemoteFindFirstPrinterChangeNotification_ request to the print spooler, which is a request for print clients to subscribe to notifications of changes on the print server, this makes the victim computer account authenticate back to SpoolSample.

To escalate from Domain Admins in a child domain to Enterprise Admins, you need:

- Admin access on a child domain server that has a service configured with unconstrained delegation.
    
    - Any DC will have unconstrained delegation enabled.
        
    - Alternatively, it is possible if you have compromised a system and access to set the userAccountControl attribute of the computer’s AD object.
        
- Existence of a privileged server in the root domain with an exposed print spooler service.
    
    - Windows computers have the print spooler service running by default (even DCs).
        

Using a compromised child domain DC we can get a TGT as a DC in the root domain. This root DC TGT can be used to DCSync the root domain which compromises the root domain.

SpecterOps, who founds this attack path, made an excellent [figure](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1) giving an overview of the attack performed between two forests, but the principles are the same for two intra-forest domains:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/06e1fe7e-63bb-45f5-b738-2af00b9e3f94/image13.png)

First Rubeus is set to monitor the memory of our compromised computer for Kerberos tickets for the ROOT DC computer account ROOT-DC-01:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/413e9c73-7abd-4c0c-aacb-ad90908875ea/image14.png)

> |Argument|Info|
> |---|---|
> |`monitor`|Tells Rubeus to start monitoring and print captured TGTs.|
> |`/monitorinterval:<seconds>`|Monitor for new tickets every n-seconds.|
> |`/filteruser:<user or computername>`|The argument is also named ‘/targetuser’.|
> |`/nowrap`|Tells Rubeus to print the ticket as base64 without wrapping the text.|

We then run SpoolSample:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/39a9e5df-4105-4767-aa95-36aa253cf84e/image15.png)

> |Argument|Info|
> |---|---|
> |`<target system>`|The target system in the root domain (root-dc-root.local).|
> |`<compromised system>`|The compromised system in the child domain (child-dc-01.child.root.local).|

The attack succeeds and Rubeus reports that a TGT for ROOT-DC-01 has appeared in memory:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/bb274777-62db-40ec-8ff7-037640342056/image15.png)

We can abuse this TGT to get a service ticket for LDAP as ROOT-DC-01 against the DC itself. We use Rubeus to send a TGS-REQ:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/9f4e3242-a993-48a3-8aa1-710b777e3421/image16.png)

> |Argument|Info|
> |---|---|
> |`asktgs`|Tells Rubeus to request a service ticket (TGS-REQ).|
> |`/service:<SPN>`|SPN of the service we want a ticket for. We choose LDAP as that is what we need for the DCSync attack.|
> |`/dc:<root DC>`|DNS name of root DC.|
> |`/ticket:<TGT>`|The previously captured TGT in base64.|
> |`/ptt`|Tells Rubeus to inject the service ticket into memory.|

With the service ticket in memory, we can use the rights of the ticket to perform a DCSync attack. The DCSync will retrieve the Kerberos secret keys of krbtgt in the ROOT domain and is performed using Mimikatz:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/ccbea3af-b34a-4427-badc-a3dec6465242/image17.png)

> |Argument|Info|
> |---|---|
> |`lsadump::dcsync`|Tells Mimikaz to do a DCSync attack.|
> |`/domain:<domain name>`|Parent domain DNS name.|
> |`/user:<domain\username>`|Username which the DCSync attack will target and extracts secret keys of.|

Now that we have the krbtgt secret keys of the ROOT domain, we can create a golden ticket for the ROOT domain as the built-in Administrator account with group membership of Enterprise Admins:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/2702e483-e54b-41f0-a169-e0b7d383238a/image18.png)

> |Argument|Info|
> |---|---|
> |`golden`|Tells Rubeus to generate a golden ticket.|
> |`/user:<username>`|Username in root domain which the TGT will represent.|
> |`/id:<user RID>`|RID of the root domain user the ticket is forged to.|
> |`/domain:<child domain>`|Child domain DNS name.|
> |`/sid:<child domain SID>`|SID of the root domain.|
> |`/groups:<RIDs>`|RIDs of domain groups from root domain of which the user is a member. Will be set in GroupIds attribute of the PAC. RID 513 is Domain Users, RID 519 is Enterprise Admins.|
> |`/aes256:<krbtgt secret AES256 key>`|Root domain’s krbtgt secret AES256 key to encrypt the ticket.|
> |`/ptt`|Tells Rubeus to inject the TGT into memory.|

Finally, we can access the ROOT DC as Enterprise Admins:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/e8de0ccb-ef84-4e45-9af0-ac573f4ac92c/image19.png)

# Part 2 conclusion

This post demonstrated three known methods that attackers can use to escalate from Domain Admin in a child domain to Enterprise Admins. In the next post of this series, part 3: [SID filtering explained](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained), we demonstrate how SID filtering can prevent the demonstrated attacks.