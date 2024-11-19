# Define the root directory, excluded folder, and the file extensions
$RootDirectory = "C:\"
$ExcludedFolder = "C:\CyberPatriot"
$Extensions = @("*.mp3", "*.mp4", "*.jpg","*.png","*.wav")

# Define system folders to exclude (e.g., Windows default locations)
$SystemFolders = @(
    "C:\Windows",
    "C:\Program Files",
    "C:\Program Files (x86)"
)

# Loop through each file extension and delete matching files
foreach ($Extension in $Extensions) {
    Get-ChildItem -Path $RootDirectory -Recurse -Filter $Extension -File |
    Where-Object {
        # Exclude files located in the excluded folder or system folders
        -not $_.FullName.StartsWith($ExcludedFolder) -and
        -not ($SystemFolders | ForEach-Object { $_ -and $_.StartsWith($_.DirectoryName) })
    } |
    ForEach-Object {
        Write-Host "Deleting file: $($_.FullName)"
        Remove-Item -Path $_.FullName -Force
    }
}
