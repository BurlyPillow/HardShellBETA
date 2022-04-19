$PORTBlck = Read-Host "Which port number do you wish to block? (type 0 to skip)"



if ($PORTBlck -eq 0){

"Skipping Port Block..."


}


{

if ($PORTBlck -eq 7){

$7TCPUDP = Read-Host "TCP, UDP, or both?"
}




if ($7TCPUDP -eq 'TCP'){

New-NetFirewallRule -DisplayName "Blocking Port 7" -LocalPort 7 -Protocol TCP -Action Block
}



if ($7TCPUDP -eq 'UDP'){ 

New-NetFirewallRule -DisplayName "Blocking Port 7" -LocalPort 7 -Protocol UDP -Action Block
}


if ($7TCPUDP -eq 'both'){

New-NetFirewallRule -DisplayName "Blocking Port 7" -LocalPort 7 -Protocol TCP -Action Block

New-NetFirewallRule  -LocalPort 7 -Protocol UDP -Action Block

}

} #Port 7

{

if ($PORTBlck -eq 19){

$19TCPUDP = Read-Host "TCP, UDP, or both?"
}


if ($19TCPUDP -eq 'TCP'){

New-NetFirewallRule -DisplayName "Blocking Port 19" -LocalPort 19 -Protocol TCP -Action Block
}





if ($19TCPUDP -eq 'UDP'){

New-NetFirewallRule -DisplayName "Blocking Port 19" -LocalPort 19 -Protocol UDP -Action Block

}


if ($19TCPUDP -eq 'both'){


New-NetFirewallRule -DisplayName "Blocking Port 19" -LocalPort 19 -Protocol TCP -Action Block

New-NetFirewallRule  -LocalPort 19 -Protocol UDP -Action Block



}


} #Port 19


if ($PORTBlck -eq 20){



New-NetFirewallRule -DisplayName "Blocking Port 20" -LocalPort 20 -Protocol TCP -Action Block

} #Port 20






if ($PORTBlck -eq 21){



New-NetFirewallRule -DisplayName "Blocking Port 21" -LocalPort 21 -Protocol TCP -Action Block

} #Port 21




if ($PORTBlck -eq 22){



New-NetFirewallRule -DisplayName "Blocking Port 22" -LocalPort 22 -Protocol TCP -Action Block

} #Port 22



if ($PORTBlck -eq 23){



New-NetFirewallRule -DisplayName "Blocking Port 23" -LocalPort 23 -Protocol TCP -Action Block

} #Port 23





if ($PORTBlck -eq 25){



New-NetFirewallRule -DisplayName "Blocking Port 25" -LocalPort 21 -Protocol TCP -Action Block

} #Port 25


if ($PORTBlck -eq 37){

$37TCPUDP = Read-Host "TCP, UDP, or both?"

}



if ($37TCPUDP -eq 'TCP'){


New-NetFirewallRule -DisplayName "Blocking Port 37" -LocalPort 37 -Protocol TCP -Action Block


}

if ($37TCPUDP -eq 'UDP'){

New-NetFirewallRule -DisplayName "Blocking Port 37" -LocalPort 37 -Protocol UDP -Action Block



}



if ($37TCPUDP -eq 'both'){

New-NetFirewallRule -DisplayName "Blocking Port 37" -LocalPort 37 -Protocol UDP -Action Block

New-NetFirewallRule -LocalPort 37 -Protocol TCP -Action Block




if ($PORTBlck -eq 80){

New-NetFirewallRule -DisplayName "Blocking Outbound Port 80" -Direction Outbound -LocalPort 80 -Protocol UDP -Action Block


}




 
