Start-Process -FilePath "rundll32" -ArgumentList "setupapi,InstallHinfSection DefaultInstall 132 (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/moonmantee/CyberpatriotScript/Server2022SecPolTemplate.inf' -OutFile 'C:\template.inf'); 'C:\template.inf'" -Verb RunAs

