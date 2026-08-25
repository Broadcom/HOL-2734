# ======================================================================
# vSAN 9.1 ESA Multi-Site Cluster & Host Service Reconfiguration
# (Automated CI/CD Deployment Version)
# ======================================================================

Import-Module VMware.VimAutomation.Core
Import-Module VMware.VimAutomation.Storage

# ----------------------------------------------------------------------
# CONFIGURATION VARIABLES
# ----------------------------------------------------------------------
$globalUser     = "administrator@vsphere.local"
$globalPass     = "VMware123!VMware123!"
$policyName     = "vSAN ESA Auto RAID Policy"
$vmNamePattern  = "*"

# Cluster that requires DRS automation level to be explicitly set
$drsTargetCluster = "cluster-mgmt-01b"

# Specific ESXi hosts requiring the DPD service to be enabled/started
$dpdTargetHosts = @(
    "esx-10a.site-a.vcf.lab",
    "esx-11a.site-a.vcf.lab"
)

# Regex pattern to exclude VMs starting with acct-, sales-, dev-, or "vSAN File"
$vmExcludeRegex = '^(acct-|sales-|dev-|vSAN[\s_-]?File)'

# Topology Definition
$sites = @(
    @{
        vCenter  = "vc-mgmt-a.site-a.vcf.lab"
        Clusters = @(
            @{ Name = "cluster-mgmt-01a"; Datastore = "vsan-mgmt-01a" },
            @{ Name = "cluster-esa-01a"; Datastore = "vsan-esa-01a" }
        )
    },
    @{
        vCenter  = "vc-mgmt-b.site-b.vcf.lab"
        Clusters = @(
            @{ Name = "cluster-mgmt-01b"; Datastore = "vsan-mgmt-01b" },
            @{ Name = "cluster-vsan_storage-01b"; Datastore = "vsan_StorageCluster_DS" }
        )
    }
)

# Enable multiple concurrent vCenter connections & bypass self-signed certs
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# ======================================================================
# vSAN ESA CLUSTER & VM STORAGE POLICY RECONFIGURATION
# ======================================================================

foreach ($site in $sites) {
    Write-Host "`n======================================================================" -ForegroundColor Magenta
    Write-Host "CONNECTING TO VCENTER: $($site.vCenter)" -ForegroundColor Magenta
    Write-Host "======================================================================" -ForegroundColor Magenta

    try {
        $viServer = Connect-VIServer -Server $site.vCenter -User $globalUser -Password $globalPass -ErrorAction Stop
        $sessionId = $viServer.SessionId
    } catch {
        Write-Error "Failed to connect to $($site.vCenter). Skipping its clusters..."
        continue
    }

    foreach ($env in $site.Clusters) {
        Write-Host "`n--- PROCESSING CLUSTER: $($env.Name) ---" -ForegroundColor Yellow

        $cluster = Get-Cluster -Name $env.Name -Server $viServer -ErrorAction SilentlyContinue
        
        if (-not $cluster) {
            Write-Error "Could not find cluster '$($env.Name)'. Skipping..."
            continue
        }

        $clusterMoRef = $cluster.ExtensionData.MoRef.Value

        # ------------------------------------------------------------------
        # STEP 1: Ensure DRS Automation Level is set to FullyAutomated
        # ------------------------------------------------------------------
        if ($env.Name -eq $drsTargetCluster) {
            Write-Host "Checking DRS automation level for '$($env.Name)'..." -ForegroundColor Cyan
            
            if ($cluster.DrsAutomationLevel -ne "FullyAutomated") {
                Write-Host "  -> Current DRS level is '$($cluster.DrsAutomationLevel)'. Updating to 'FullyAutomated'..." -ForegroundColor Cyan
                Set-Cluster -Cluster $cluster -DrsAutomationLevel FullyAutomated -Confirm:$false | Out-Null
                Write-Host "  -> Successfully updated DRS to FullyAutomated on $($env.Name)!" -ForegroundColor Green
            } else {
                Write-Host "  -> DRS is already set to FullyAutomated on $($env.Name)." -ForegroundColor Green
            }
        }

        # ------------------------------------------------------------------
        # STEP 2: Enable & Start DPD Service (/etc/init.d/dpd)
        # ------------------------------------------------------------------
        foreach ($hostName in $dpdTargetHosts) {
            $esxHost = Get-VMHost -Name $hostName -Location $cluster -Server $viServer -ErrorAction SilentlyContinue
            if ($esxHost) {
                Write-Host "Configuring DPD Service (/etc/init.d/dpd) on Host: $hostName..." -ForegroundColor Cyan
                
                $dpdService = $esxHost | Get-VMHostService | Where-Object { $_.Key -eq "dpd" -or $_.Label -match "dpd" }

                if ($dpdService) {
                    Set-VMHostService -HostService $dpdService -Policy "On" -Confirm:$false | Out-Null
                    if (-not $dpdService.Running) {
                        Start-VMHostService -HostService $dpdService -Confirm:$false | Out-Null
                        Write-Host "  -> DPD Service started and set to Automatic on $hostName." -ForegroundColor Green
                    } else {
                        Write-Host "  -> DPD Service is already running on $hostName." -ForegroundColor Green
                    }
                } else {
                    try {
                        $esxcli = Get-EsxCli -VMHost $esxHost -V2
                        $esxcli.system.service.start.Invoke(@{servicename = "dpd"}) | Out-Null
                        $esxcli.system.service.set.Invoke(@{servicename = "dpd"; enabled = $true}) | Out-Null
                        Write-Host "  -> DPD Service started via ESXCLI on $hostName." -ForegroundColor Green
                    } catch {
                        Write-Error "  -> Failed to start DPD service on host '$hostName': $_"
                    }
                }
            }
        }

        # ------------------------------------------------------------------
        # STEP 3: Disable Auto Policy Management (Internal SOAP Payload)
        # ------------------------------------------------------------------
        Write-Host "Reconfiguring '$($env.Name)': Auto Policy Management = OFF | Auto RAID = ON..." -ForegroundColor Cyan

        $soapBody = @"
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Body>
    <VsanClusterReconfig xmlns="urn:internalvsan">
      <_this xmlns="urn:internalvim25" type="VsanVcClusterConfigSystem">vsan-cluster-config-system</_this>
      <cluster xmlns="urn:internalvim25" type="ClusterComputeResource">$clusterMoRef</cluster>
      <vsanReconfigSpec xmlns="urn:internalvim25">
        <vsanClusterConfig>
          <vsanCyberRecoveryEnabled>false</vsanCyberRecoveryEnabled>
        </vsanClusterConfig>
        <modify>true</modify>
        <vsanEsaConfig xmlns="urn:internalvsan">
          <hclDiskClaimEnabled>true</hclDiskClaimEnabled>
          <datastoreDefaultPolicySelectionConfig>
            <enabled>false</enabled>
          </datastoreDefaultPolicySelectionConfig>
          <autoRAIDConfig>
            <assumeAutoManagedRAID>true</assumeAutoManagedRAID>
          </autoRAIDConfig>
        </vsanEsaConfig>
      </vsanReconfigSpec>
    </VsanClusterReconfig>
  </Body>
</Envelope>
"@

        $uri = "https://$($site.vCenter)/vsanHealth"
        $headers = @{
            "SOAPAction" = "urn:internalvsan/dev.version"
            "Cookie"     = "vmware_soap_session=$sessionId"
        }

        try {
            $response = Invoke-WebRequest -Uri $uri -Method Post -ContentType "text/xml; charset=utf-8" -Headers $headers -Body $soapBody -SkipCertificateCheck
            
            if ($response.StatusCode -eq 200) {
                Write-Host "  -> Successfully disabled Auto Policy Management!" -ForegroundColor Green
            } else {
                Write-Host "  -> Received unusual status: $($response.StatusCode)" -ForegroundColor Yellow
            }
        } catch {
            Write-Error "  -> Failed to execute API call: $_"
        }

        # ------------------------------------------------------------------
        # STEP 4: Change Default Storage Policy for the vSAN Datastore
        # ------------------------------------------------------------------
        Write-Host "Setting default policy for datastore '$($env.Datastore)' to '$policyName'..." -ForegroundColor Cyan
        
        $ds = Get-Datastore -Name $env.Datastore -Server $viServer -ErrorAction SilentlyContinue
        $targetPolicy = Get-SpbmStoragePolicy -Name $policyName -Server $viServer -ErrorAction SilentlyContinue

        if ($ds -and $targetPolicy) {
            $ds | Get-SpbmEntityConfiguration | Set-SpbmEntityConfiguration -StoragePolicy $targetPolicy -Confirm:$false | Out-Null
            Write-Host "  -> Datastore policy updated successfully." -ForegroundColor Green
        } else {
            Write-Error "  -> Could not locate Datastore '$($env.Datastore)' or Policy '$policyName'."
        }

        # ------------------------------------------------------------------
        # STEP 5: Change Storage Policy for Target Group of VMs
        # Excludes VMs starting with: acct-, sales-, dev-, or "vSAN File"
        # ------------------------------------------------------------------
        $vms = Get-VM -Location $cluster -Name $vmNamePattern -Server $viServer -ErrorAction SilentlyContinue | 
               Where-Object { $_.Name -notmatch $vmExcludeRegex }

        if ($vms) {
            Write-Host "Updating storage policies for $(($vms).Count) VMs in $($env.Name)..." -ForegroundColor Cyan

            foreach ($vm in $vms) {
                $vm | Get-SpbmEntityConfiguration | Set-SpbmEntityConfiguration -StoragePolicy $targetPolicy -Confirm:$false | Out-Null
                $vm | Get-HardDisk | Get-SpbmEntityConfiguration | Set-SpbmEntityConfiguration -StoragePolicy $targetPolicy -Confirm:$false | Out-Null
                Write-Host "  -> Reassigned policy for VM: $($vm.Name)" -ForegroundColor Green
            }
        } else {
            Write-Host "  -> No eligible VMs found in cluster '$($env.Name)'." -ForegroundColor Yellow
        }
    }
}

# Clean disconnect from all connected vCenters
Disconnect-VIServer -Server * -Confirm:$false -ErrorAction SilentlyContinue
