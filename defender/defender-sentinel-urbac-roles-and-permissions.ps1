
# per role - name, ID and each permission bucket, nothing truncated
Get-AzRoleDefinition |
    Where-Object Name -Like "Defender Unified RBAC*" |
    ForEach-Object {
        [pscustomobject]@{
            Role           = $_.Name
            Id             = $_.Id
            Actions        = (($_.Permissions.Actions        + $_.Permissions.Action)        | Where-Object { $_ }) -join "; "
            NotActions     = (($_.Permissions.NotActions     + $_.Permissions.NotAction)     | Where-Object { $_ }) -join "; "
            DataActions    = (($_.Permissions.DataActions    + $_.Permissions.DataAction)    | Where-Object { $_ }) -join "; "
            NotDataActions = (($_.Permissions.NotDataActions + $_.Permissions.NotDataAction) | Where-Object { $_ }) -join "; "
        }
    } | Format-List

# role and its permissions list view - one row per permission
Get-AzRoleDefinition |
    Where-Object Name -Like "Defender Unified RBAC*" |
    ForEach-Object {
        $role = $_
        foreach ($set in $role.Permissions) {
            $set.PSObject.Properties |
                Where-Object Name -Match '^(Not)?(Data)?Actions?$' |
                ForEach-Object {
                    $type = $_.Name -replace 's$'
                    foreach ($permission in $_.Value) {
                        [pscustomobject]@{
                            Role       = $role.Name
                            Id         = $role.Id
                            Type       = $type
                            Permission = $permission
                        }
                    }
                }
        }
    } | Sort-Object Role, Type, Permission | Format-Table -AutoSize

# classic azure rbac sentinel roles
Get-AzRoleDefinition | Where-Object Name -Like "Microsoft Sentinel*" |
	ForEach-Object {
		$role = $_
		foreach ($set in $role.Permissions) {
			$set.PSObject.Properties |
				Where-Object Name -Match '^(Not)?(Data)?Actions?$' |
				ForEach-Object {
					$type = $_.Name -replace 's$'
					foreach ($permission in $_.Value) {
						[pscustomobject]@{
							Role       = $role.Name
							Id         = $role.Id
							Type       = $type
							Permission = $permission
						}
					}
				}
		}
	} | Sort-Object Role, Type, Permission | Format-Table -AutoSize
	