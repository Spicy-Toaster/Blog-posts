Originally published on https://blog.improsec.com March 5th 2024. 
https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have
_Authors: Jakob Mollerup and Tobias Torp._
On a recent assignment, we recently ran into a curiosity. On a server, there was a service account running a service that it shouldn’t be able to run.  This was in a tiered AD where permissions were configured with very fine-grained access.  

We figured it ran on a previously approved session. However, when we restarted the service and then restarted the server, it started running again with no problem. This seemed very strange. The account running the service wasn’t being denied access, but it also wasn’t being allowed.    
So how could it have permission to run a service when said permission wasn’t defined anywhere? 

Clearly, the permission was being defined somewhere. But where? We began going through the objects that were given the “Log on as a service” permissions in the User Rights Assignment of the Local Policy. 

It looked mostly standard. However, one of the groups listed was NT AUTHORITY\SERVICE, which is not default.  

There is very little Microsoft documentation on what exactly this group does. All we could find was the following three mentions on pages with well-known SIDs.  

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/f2c2e8d4-b7b0-4ae7-be7e-5dbc8f76bc36/Picture1.png)

_Figure 1. Description of NT AUTHORITY\SERVICE_ [**_[1]_**](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftn1)

[_[1]_](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftnref1) [_Security identifiers | Microsoft Learn_](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/db1fca6f-3bb8-45ff-866c-88f3d0864c23/Picture2.png)

_Figure 2. Description of NT AUTHORITY\SERVICE_ [**_[2]_**](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftn1)

[_[2]_](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftnref1) [_[MS-DTYP]: Well-Known SID Structures | Microsoft Learn_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/2abd0f22-8055-4d67-b32e-9fd9f670d882/Picture3.png)

_Figure 3. Description of NT AUTHORITY\SERVICE_ [_[3]_](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftn1)

[_[3]_](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftnref1) [_Well-known SIDs - Win32 apps | Microsoft Learn_](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)

Some might look at this and go; “Well that makes sense”, however we are not some of those people. So, we set up a lab and started testing to figure out the permissions that NT AUTHORITY\SERVICE gives.

First, we simply recreated what we ran into in the wild.  
We configured our own service called “ExampleService” and set it up to run with the domain account ROOT\ServiceAccount and then configured NT AUTHORITY\SERVICE to have the permission “Log on as a service”.

This can be seen in Figure 4.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/29e5916e-1202-4498-aae1-b12caf084655/Picture4.png)

_Figure 4. ExampleService running as a member of NT AUTHORITY\SERVICE_

When we restarted our service “ExampleService” it started up again, running happily and without any problems.

This is an issue as the account we are using to run the service ROOT\ServiceAccount is completely new, and we knew that no permissions had been given to the account to log on to the computer and we had removed the default login permission given to the account when configuring it to run a service.

Next, we wanted to check if we could block accounts from logging on, or if NT AUTHORITY\SERVICE takes precedence.

In Figure 5 NT AUTHORITY\SERVICE still has permission to “Log on as a service” but we have added ROOT\ServiceAccount to the URA “Deny log on as a service”.  
The result when we tried to start up ExampleService was the lovely error that tells us the service could not start due to a logon failure. This is what we wanted.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/08a490a8-8a2d-45bf-b2be-988ded222cc7/Picture5.png)

_Figure 5. ExampleService is unable to run when blocked_

Our testing in combination with Microsoft's description “_A group that includes all security principals that have signed in as a service_” seems to mean that the effect of NT AUTHORITY\SERVICE being given the right to “Log on as a service”, means that all local accounts and every account in the domain that is not explicitly denied from accessing the computer is being given the permission to run a service as long as it is configured as a service.

The meaning of the description _“A group that includes all security principals that have signed in as a service. “_ is that every account that signs in is included in the virtual group NT AUTHORITY\SERVICE.  
When that group is then given the right to “Log on as a service” it is every account that is logged in as a service that can then run a service.

It is however important to remember that it is only accounts that have been configured to run as a service that is being given the right to run if NT AUTHORITY\SERVICE is given the right “Log on as a service”.  
And to configure an account to run as a service administrative rights are needed.

Next, we wanted to see how we can make a configuration so that only when an account is explicitly given permission it can log on as a service.

We looked up the default setting that gives the right to “Log on as a service” when Windows is installed, NT SERVICE\ALL SERVICES.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/56e53498-35b9-49eb-a82a-455dc06f75e7/Picture6.png)

_Figure 6. Description of NT SERVICE\ALL SERVICES_ [**_[4]_**](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftn1)

[_[4]_](https://blog.improsec.com/tech-blog/virtual-microsoft-service-groups-what-effect-do-they-have#_ftnref1) [_Security identifiers | Microsoft Learn_](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)  _&_ [_[MS-DTYP]: Well-Known SID Structures | Microsoft Learn_](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)

Again, the description is not very clear on what the effect of this group is.

After testing it was clear that the effect is that only the user given explicitly the right to run a service can do so. As seen in Figure 7, when we tried to start ExampleService with only NT SERVICE\ALL SERVICES given the right to “Log on as a service” we received an error due to login failure.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/0d5adf91-f397-4db7-989d-d42f5fba20d4/Picture7.png)

_Figure 7. ExampleService can't run without explicit permission when NT SERVICE\ALL SERVICES is used_

When ROOT\ServiceAccount was also given the right to “Log on as a service” along with NT SERVICE\ALL SERVICES ExampleService can start and run.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/c377b2bf-b13a-40c0-9160-7e1c053f7bb5/Picture8.png)

_Figure 8. ExampleService running only when ServiceAccount has explicitly been given permission_

This makes it look like NT SERVICE\ALL SERVICES is not necessary. ExampleService can run with and without NT SERVICE\ALL SERVICES being allowed, and so could Local Service, Local System, and Network Service when we tested them.

However, if NT SERVICE\ALL SERVICES is not allowed to log on as a service, all the services that are often installed on a server will not be able to run.  
We tested this by installing an SQL server in our lab. As can be seen in figure 9 no one has been given the Log on as a service permission. When attempting to start the services necessary to run a SQL server we get a logon error.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/ccd0dc7d-3484-4092-b619-02d45dedf20f/Picture9.png)

_Figure 9. NT SERVICE\ services is unable to run_

In Figure 10, NT SERVICE\ALL SERVICES have been given permission to log on as a service again, and the SQL-associated services have been started and are running.

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/ece23648-17ec-4c97-9722-4f5883743a13/Picture10.png)

_Figure 10. NT SERVICE\ services can run._

So, to sum it all up, NT AUTHORITY\SERVICE gives every account that is logged on as a service the right to run a service whereas NT SERVICE\ALL SERVICES allows the services that run in the context of NT SERVICE to log on as a service.

NT SERVICE\ALL SERVICES is by default given the log-on as a service permission with very good reason and should not be removed.

We couldn’t figure out a secure use case for NT AUTHORITY\SERVICE but it is probably out there.