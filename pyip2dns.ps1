#Inputfile: ip.txt
#Outputfile: dns.csv
$list = Get-Content "ip.txt"
$stream = [System.IO.StreamWriter] "dns.csv"
$stream.WriteLine("IP;DNS")
$counter=0
ForEach($ip In $list)
{
$counter++
write-output("$counter $ip");
$stream.Write($ip)

$dns="";
    try
    {
    $dns=[System.Net.Dns]::GetHostEntry($ip) 
    foreach ($d in $dns) 
        { 
        $stream.Write(";")
        $stream.Write('"')
        $stream.Write($d.Hostname)
        $stream.Write('"')
        }
    $stream.WriteLine()
    }
    catch
    {
    $stream.WriteLine(';"DNS n/a"')
    }
}
$stream.close()

