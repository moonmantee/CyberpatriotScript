# Download security template, and import the local template
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/moonmantee/CyberpatriotScript/main/Windows/Server2022SecPolTemplate.inf' -OutFile 'C:\template.inf'
secedit /import /db C:\Windows\security\database\secedit.sdb /cfg C:\template.inf


