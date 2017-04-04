#$BaseLinePath = 'F:\Project\Baselines\'
$BaseLinePath = "$home\desktop\"
$RootDomainBaseline = 'XYZ123'
$ChildDomainBaseline = 'AA123'

$Root = "DC=$RootDomainBaseline,DC=com"
$Child = "DC=$ChildDomainBaseline,DC=$RootDomainBaseline,DC=com"

dir $BaseLinePath -File -Recurse  | ForEach-Object {

    $new = gc $_.FullName | foreach-object {
       
       $_ -replace "DC=US,DC=Contoso,DC=com",$Child

    }

    sc -path $_.fullname -Value $new
}


dir $BaseLinePath -File -Recurse  | ForEach-Object {

    $new = gc $_.FullName | foreach-object {
       
       $_ -replace "DC=Contoso,DC=com",$Root

    }

    sc -path $_.fullname -Value $new
}


dir $BaseLinePath -File -Recurse  | ForEach-Object {

    $new = gc $_.FullName | foreach-object {
       
       $_ -replace "Contoso\\","$RootDomainBaseline\"

    }

    sc -path $_.fullname -Value $new
}


dir $BaseLinePath -File -Recurse  | ForEach-Object {

    $new = gc $_.FullName | foreach-object {
       
       $_ -replace "US\\","$ChildDomainBaseline\"

    }

    sc -path $_.fullname -Value $new
}