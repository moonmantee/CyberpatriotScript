$url = "https://github.com/moonmantee/CyberpatriotScript/archive/refs/heads/main.zip"
$output = "repo.zip"
Invoke-WebRequest -Uri $url -OutFile $output
$destination = "C:\repo-folder"
Expand-Archive -Path $output -DestinationPath $destination
cd $destination
cd ".\CyberpatriotScript-main\Windows"
Set-ExecutionPolicy RemoteSigned
.\main.ps1
