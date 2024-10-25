Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/moonmantee/CyberpatriotScript/main/Server2022SecPolTemplate.inf' -OutFile 'C:\template.inf'
secedit /import /db C:\Windows\security\database\secedit.sdb /cfg C:\template.inf
