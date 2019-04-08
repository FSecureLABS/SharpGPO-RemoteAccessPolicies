# SharpGPO-RemoteAccessPolicies
A C# tool for enumerating remote access policies through group policy.

## Compile Instructions ## 

SharpExchangePriv has been built against .NET 4.0 and is compatible with Visual Studio 2015/2017. Simply open the solution file and build the project.

CommandLineParser has been used in order to parse the command line arguments. This will create the `CommandLine.dll` file, along with the executable. You can simple merge the .exe and the .dll into one executable file:

`ILMerge.exe /out:C:\SharpGPO-RemoteAccessPolicies.exe C:\Release\SharpGPO-RemoteAccessPolicies.exe C:\Release\CommandLine.dll`

## Usage ##

#### `--domain`

Specifies an Active Directory server (domain controller) to bind to

#### `--domainController`

Specifies an Active Directory server (domain controller) to bind to

#### `--searchScope`

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree)

#### `--searchBase`

The LDAP source to search through, e.g. SharpGPO-RemoteAccessPolicies --searchBase /OU=Workstations,DC=domain,DC=local. Useful for OU queries.

#### `--verbose`

Print more information about GPOs

## Example ##

```
C:\Users\IEUser\Desktop>SharpGPO-RemoteAccessPolicies.exe

[-] Domain Controller is: DC1.skipper.loc
[-] Domain is: skipper.loc


[+] EnableLUA:                          WIN10.skipper.loc WIN7.skipper.loc
[+] FilterAdministratorToken:           WIN10.skipper.loc BWIN7.skipper.loc
[+] LocalAccountTokenFilterPolicy:      WIN10.skipper.loc WIN7.skipper.loc
[+] SeDenyNetworkLogonRight:            WIN10.skipper.loc WIN7.skipper.loc
[+] SeDenyRemoteInteractiveLogonRight:  WIN10.skipper.loc WIN7.skipper.loc
```

## License ##

The cookbook is released under a 3-clause BSD License and maintained by [MWR Info-Security](https://mwrinfosecurity.com/). See the `LICENSE` file for details.

## Contact ##

Please submit any bugs on the Github project page or give me a shout on twitter [@den_n1s](https://twitter.com/den_n1s)
