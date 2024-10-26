$url = "https://github.com/moonmantee/CyberpatriotScript/archive/refs/heads/main.zip"
$output = "repo.zip"
Invoke-WebRequest -Uri $url -OutFile $output
$destination = "C:\repo-folder"
Expand-Archive -Path $output -DestinationPath $destination
cd $destination
.\main.ps1
