param serverfarms_bluecorp_ASP_name string = 'bluecorp-ASP'
param sites_bluecorp_order_service_name string = 'bluecorp-order-service' //functionapp
param storageAccounts_logisticsftp_name string = 'logisticsftp'
param storageAccounts_bluecorpazstorage_name string = 'bluecorpazstorage'
param components_bluecorp_order_service_name string = 'bluecorp-order-service'
param actionGroups_Application_Insights_Smart_Detection_name string = 'Application Insights Smart Detection'
param components_log_analytics_workspace_name string = 'log-analytics-workspace'
param location string = resourceGroup().location

resource actionGroups_Application_Insights_Smart_Detection_name_resource 'microsoft.insights/actionGroups@2023-09-01-preview' = {
  name: actionGroups_Application_Insights_Smart_Detection_name
  location: 'Global'
  properties: {
    groupShortName: 'SmartDetect'
    enabled: true
    emailReceivers: []
    smsReceivers: []
    webhookReceivers: []
    eventHubReceivers: []
    itsmReceivers: []
    azureAppPushReceivers: []
    automationRunbookReceivers: []
    voiceReceivers: []
    logicAppReceivers: []
    azureFunctionReceivers: []
    armRoleReceivers: [
      {
        name: 'Monitoring Contributor'
        roleId: '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
        useCommonAlertSchema: true
      }
      {
        name: 'Monitoring Reader'
        roleId: '43d0d8ad-25c7-4714-9337-8ba259a9fe05'
        useCommonAlertSchema: true
      }
    ]
  }
}

resource components_log_analytics_workspace_name_resource 'Microsoft.OperationalInsights/workspaces@2020-08-01' = {
  name: components_log_analytics_workspace_name
  location: location
  sku: {
    name: 'PerGB2018'
  }
  properties: {
    retentionInDays: 30
  }
}

resource components_bluecorp_order_service_name_resource 'microsoft.insights/components@2020-02-02' = {
  name: components_bluecorp_order_service_name
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Flow_Type: 'Redfield'
    Request_Source: 'IbizaWebAppExtensionCreate'
    RetentionInDays: 90
    WorkspaceResourceId: components_log_analytics_workspace_name_resource.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource storageAccounts_logisticsftp_name_resource 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccounts_logisticsftp_name
  location: location
  sku: {
    name: 'Standard_RAGRS'
    tier: 'Standard'
  }
  kind: 'StorageV2'
  properties: {
    dnsEndpointType: 'Standard'
    defaultToOAuthAuthentication: false
    publicNetworkAccess: 'Enabled'
    allowCrossTenantReplication: false
    isLocalUserEnabled: true
    isSftpEnabled: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    largeFileSharesState: 'Enabled'
    isHnsEnabled: true
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: []
      ipRules: []
      defaultAction: 'Allow'
    }
    supportsHttpsTrafficOnly: true
    encryption: {
      requireInfrastructureEncryption: false
      services: {
        file: {
          keyType: 'Account'
          enabled: true
        }
        blob: {
          keyType: 'Account'
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    accessTier: 'Cool'
  }
}

resource storageAccounts_bluecorpazstorage_name_resource 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccounts_bluecorpazstorage_name
  location: location
  tags: {
    'ms-resource-usage': 'azure-cloud-shell'
  }
  sku: {
    name: 'Standard_LRS'
    tier: 'Standard'
  }
  kind: 'StorageV2'
  properties: {
    allowCrossTenantReplication: false
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: []
      ipRules: []
      defaultAction: 'Allow'
    }
    supportsHttpsTrafficOnly: true
    encryption: {
      services: {
        file: {
          keyType: 'Account'
          enabled: true
        }
        blob: {
          keyType: 'Account'
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    accessTier: 'Hot'
  }
}

resource serverfarms_bluecorp_ASP_name_resource 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: serverfarms_bluecorp_ASP_name
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
    size: 'B1'
    family: 'B'
    capacity: 1
  }
  kind: 'linux'
  properties: {
    perSiteScaling: false
    elasticScaleEnabled: false
    maximumElasticWorkerCount: 1
    isSpot: false
    freeOfferExpirationTime: '2025-02-05T09:34:55.5266667'
    reserved: true
    isXenon: false
    hyperV: false
    targetWorkerCount: 0
    targetWorkerSizeId: 0
    zoneRedundant: false
  }
}

resource components_bluecorp_order_service_name_degradationindependencyduration 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'degradationindependencyduration'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'degradationindependencyduration'
      DisplayName: 'Degradation in dependency duration'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_degradationinserverresponsetime 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'degradationinserverresponsetime'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'degradationinserverresponsetime'
      DisplayName: 'Degradation in server response time'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_digestMailConfiguration 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'digestMailConfiguration'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'digestMailConfiguration'
      DisplayName: 'Digest Mail Configuration'
      Description: 'This rule describes the digest mail preferences'
      HelpUrl: 'www.homail.com'
      IsHidden: true
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_extension_billingdatavolumedailyspikeextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'extension_billingdatavolumedailyspikeextension'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'extension_billingdatavolumedailyspikeextension'
      DisplayName: 'Abnormal rise in daily data volume (preview)'
      Description: 'This detection rule automatically analyzes the billing data generated by your application, and can warn you about an unusual increase in your application\'s billing costs'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/tree/master/SmartDetection/billing-data-volume-daily-spike.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_extension_canaryextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'extension_canaryextension'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'extension_canaryextension'
      DisplayName: 'Canary extension'
      Description: 'Canary extension'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/'
      IsHidden: true
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_extension_exceptionchangeextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'extension_exceptionchangeextension'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'extension_exceptionchangeextension'
      DisplayName: 'Abnormal rise in exception volume (preview)'
      Description: 'This detection rule automatically analyzes the exceptions thrown in your application, and can warn you about unusual patterns in your exception telemetry.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/abnormal-rise-in-exception-volume.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_extension_memoryleakextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'extension_memoryleakextension'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'extension_memoryleakextension'
      DisplayName: 'Potential memory leak detected (preview)'
      Description: 'This detection rule automatically analyzes the memory consumption of each process in your application, and can warn you about potential memory leaks or increased memory consumption.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/tree/master/SmartDetection/memory-leak.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_extension_securityextensionspackage 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'extension_securityextensionspackage'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'extension_securityextensionspackage'
      DisplayName: 'Potential security issue detected (preview)'
      Description: 'This detection rule automatically analyzes the telemetry generated by your application and detects potential security issues.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/application-security-detection-pack.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_extension_traceseveritydetector 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'extension_traceseveritydetector'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'extension_traceseveritydetector'
      DisplayName: 'Degradation in trace severity ratio (preview)'
      Description: 'This detection rule automatically analyzes the trace logs emitted from your application, and can warn you about unusual patterns in the severity of your trace telemetry.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/degradation-in-trace-severity-ratio.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_longdependencyduration 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'longdependencyduration'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'longdependencyduration'
      DisplayName: 'Long dependency duration'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_migrationToAlertRulesCompleted 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'migrationToAlertRulesCompleted'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'migrationToAlertRulesCompleted'
      DisplayName: 'Migration To Alert Rules Completed'
      Description: 'A configuration that controls the migration state of Smart Detection to Smart Alerts'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: true
      IsEnabledByDefault: false
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: false
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_slowpageloadtime 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'slowpageloadtime'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'slowpageloadtime'
      DisplayName: 'Slow page load time'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_bluecorp_order_service_name_slowserverresponsetime 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_bluecorp_order_service_name_resource
  name: 'slowserverresponsetime'
  location: location
  properties: {
    RuleDefinitions: {
      Name: 'slowserverresponsetime'
      DisplayName: 'Slow server response time'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource storageAccounts_logisticsftp_name_default 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccounts_logisticsftp_name_resource
  name: 'default'
  sku: {
    name: 'Standard_RAGRS'
    tier: 'Standard'
  }
  properties: {
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    cors: {
      corsRules: []
    }
    deleteRetentionPolicy: {
      allowPermanentDelete: false
      enabled: true
      days: 7
    }
  }
}

resource storageAccounts_bluecorpazstorage_name_default 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccounts_bluecorpazstorage_name_resource
  name: 'default'
  sku: {
    name: 'Standard_LRS'
    tier: 'Standard'
  }
  properties: {
    cors: {
      corsRules: []
    }
    deleteRetentionPolicy: {
      allowPermanentDelete: false
      enabled: false
    }
  }
}

resource Microsoft_Storage_storageAccounts_fileServices_storageAccounts_logisticsftp_name_default 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: storageAccounts_logisticsftp_name_resource
  name: 'default'
  sku: {
    name: 'Standard_RAGRS'
    tier: 'Standard'
  }
  properties: {
    protocolSettings: {
      smb: {}
    }
    cors: {
      corsRules: []
    }
    shareDeleteRetentionPolicy: {
      enabled: true
      days: 14
    }
  }
}

resource Microsoft_Storage_storageAccounts_fileServices_storageAccounts_bluecorpazstorage_name_default 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: storageAccounts_bluecorpazstorage_name_resource
  name: 'default'
  sku: {
    name: 'Standard_LRS'
    tier: 'Standard'
  }
  properties: {
    protocolSettings: {
      smb: {}
    }
    cors: {
      corsRules: []
    }
    shareDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource storageAccounts_logisticsftp_name_bluecorp 'Microsoft.Storage/storageAccounts/localusers@2023-05-01' = {
  parent: storageAccounts_logisticsftp_name_resource
  name: 'bluecorp'
  properties: {
    allowAclAuthorization: false
    hasSshPassword: false
    permissionScopes: [
      {
        permissions: 'rwlcd'
        service: 'blob'
        resourceName: 'bluecorp-uploads'
      }
    ]
    homeDirectory: '/bluecorp-uploads'
    hasSharedKey: false
    hasSshKey: true
  }
}

resource Microsoft_Storage_storageAccounts_queueServices_storageAccounts_logisticsftp_name_default 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storageAccounts_logisticsftp_name_resource
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
  }
}

resource Microsoft_Storage_storageAccounts_queueServices_storageAccounts_bluecorpazstorage_name_default 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storageAccounts_bluecorpazstorage_name_resource
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
  }
}

resource Microsoft_Storage_storageAccounts_tableServices_storageAccounts_logisticsftp_name_default 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storageAccounts_logisticsftp_name_resource
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
  }
}

resource Microsoft_Storage_storageAccounts_tableServices_storageAccounts_bluecorpazstorage_name_default 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storageAccounts_bluecorpazstorage_name_resource
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
  }
}

resource sites_bluecorp_order_service_name_resource 'Microsoft.Web/sites@2023-12-01' = {
  name: sites_bluecorp_order_service_name
  location: location
  kind: 'functionapp'
  properties: {   
    enabled: true
    hostNameSslStates: [
      {
        name: '${sites_bluecorp_order_service_name}.azurewebsites.net'
        sslState: 'Disabled'
        hostType: 'Standard'
      }
      {
        name: '${sites_bluecorp_order_service_name}.scm.azurewebsites.net'
        sslState: 'Disabled'
        hostType: 'Repository'
      }
    ]
    serverFarmId: serverfarms_bluecorp_ASP_name_resource.id
    reserved: true
    isXenon: false
    hyperV: false
    dnsConfiguration: {}
    vnetRouteAllEnabled: false
    vnetImagePullEnabled: false
    vnetContentShareEnabled: false
    siteConfig: {
      numberOfWorkers: 1
      linuxFxVersion: 'Python|3.11'
      acrUseManagedIdentityCreds: false
      alwaysOn: true
      http20Enabled: false
      functionAppScaleLimit: 0
      minimumElasticInstanceCount: 0
    }
    appSettings: {
      'FUNCTIONS_WORKER_RUNTIME': 'python'
      'WEBSITE_RUN_FROM_PACKAGE': '1'
      'FUNCTIONS_EXTENSION_VERSION': '~3'
    }
    scmSiteAlsoStopped: false
    clientAffinityEnabled: false
    clientCertEnabled: false
    clientCertMode: 'Required'
    hostNamesDisabled: false
    vnetBackupRestoreEnabled: false
    customDomainVerificationId: 'F21E14B6A56C0BE426B9D0405230EE8835F3616C229183A3D20966965A429772'
    containerSize: 1536
    dailyMemoryTimeQuota: 0
    httpsOnly: true
    redundancyMode: 'None'
    publicNetworkAccess: 'Enabled'
    storageAccountRequired: false
    keyVaultReferenceIdentity: 'SystemAssigned'
  }
}

resource sites_bluecorp_order_service_name_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: sites_bluecorp_order_service_name_resource
  name: 'ftp'
  location: location
  properties: {
    allow: false
  }
}

resource sites_bluecorp_order_service_name_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: sites_bluecorp_order_service_name_resource
  name: 'scm'
  location: location
  properties: {
    allow: false
  }
}

resource sites_bluecorp_order_service_name_web 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: sites_bluecorp_order_service_name_resource
  name: 'web'
  location: location
  properties: {
    numberOfWorkers: 1
    defaultDocuments: [
      'Default.htm'
      'Default.html'
      'Default.asp'
      'index.htm'
      'index.html'
      'iisstart.htm'
      'default.aspx'
      'index.php'
    ]
    netFrameworkVersion: 'v4.0'
    linuxFxVersion: 'Python|3.11'
    requestTracingEnabled: false
    remoteDebuggingEnabled: false
    httpLoggingEnabled: false
    acrUseManagedIdentityCreds: false
    logsDirectorySizeLimit: 35
    detailedErrorLoggingEnabled: false
    publishingUsername: 'REDACTED'
    scmType: 'None'
    use32BitWorkerProcess: false
    webSocketsEnabled: false
    alwaysOn: true
    managedPipelineMode: 'Integrated'
    virtualApplications: [
      {
        virtualPath: '/'
        physicalPath: 'site\\wwwroot'
        preloadEnabled: true
      }
    ]
    loadBalancing: 'LeastRequests'
    experiments: {
      rampUpRules: []
    }
    autoHealEnabled: false
    vnetRouteAllEnabled: false
    vnetPrivatePortsCount: 0
    publicNetworkAccess: 'Enabled'
    cors: {
      allowedOrigins: [
        'https://portal.azure.com'
      ]
      supportCredentials: false
    }
    localMySqlEnabled: false
    ipSecurityRestrictions: [
      {
        ipAddress: 'Any'
        action: 'Allow'
        priority: 2147483647
        name: 'Allow all'
        description: 'Allow all access'
      }
    ]
    scmIpSecurityRestrictions: [
      {
        ipAddress: 'Any'
        action: 'Allow'
        priority: 2147483647
        name: 'Allow all'
        description: 'Allow all access'
      }
    ]
    scmIpSecurityRestrictionsUseMain: false
    http20Enabled: false
    minTlsVersion: '1.2'
    scmMinTlsVersion: '1.2'
    ftpsState: 'FtpsOnly'
    preWarmedInstanceCount: 0
    functionAppScaleLimit: 0
    functionsRuntimeScaleMonitoringEnabled: false
    minimumElasticInstanceCount: 0
    azureStorageAccounts: {}
  }
}

resource sites_bluecorp_order_service_name_sites_bluecorp_order_service_name_azurewebsites_net 'Microsoft.Web/sites/hostNameBindings@2023-12-01' = {
  parent: sites_bluecorp_order_service_name_resource
  name: '${sites_bluecorp_order_service_name}.azurewebsites.net'
  location: location
  properties: {
    siteName: 'bluecorp-order-processing'
    hostNameType: 'Verified'
  }
}

resource storageAccounts_bluecorpazstorage_name_default_azure_webjobs_hosts 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: storageAccounts_bluecorpazstorage_name_default
  name: 'azure-webjobs-hosts'
  properties: {
    defaultEncryptionScope: '$account-encryption-key'
    denyEncryptionScopeOverride: false
    publicAccess: 'None'
  }
  //removed ImmutableStorageWithVersioning
}

resource storageAccounts_bluecorpazstorage_name_default_azure_webjobs_secrets 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: storageAccounts_bluecorpazstorage_name_default
  name: 'azure-webjobs-secrets'
  properties: {
    defaultEncryptionScope: '$account-encryption-key'
    denyEncryptionScopeOverride: false
    publicAccess: 'None'
  }
  //removed ImmutableStorageWithVersioning
}

resource storageAccounts_logisticsftp_name_default_bluecorp_uploads 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: storageAccounts_logisticsftp_name_default
  name: 'bluecorp-uploads'
  properties: {
    defaultEncryptionScope: '$account-encryption-key'
    denyEncryptionScopeOverride: false
    publicAccess: 'None'
  }
  //removed ImmutableStorageWithVersioning
}

resource storageAccounts_bluecorpazstorage_name_default_bluecorpresources 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: Microsoft_Storage_storageAccounts_fileServices_storageAccounts_bluecorpazstorage_name_default
  name: 'bluecorpresources'
  properties: {
    accessTier: 'TransactionOptimized'
    shareQuota: 6
    enabledProtocols: 'SMB'
  }
}

resource storageAccounts_bluecorpazstorage_name_default_AzureFunctionsDiagnosticEvents202501 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: Microsoft_Storage_storageAccounts_tableServices_storageAccounts_bluecorpazstorage_name_default
  name: 'AzureFunctionsDiagnosticEvents202501'
  properties: {}

}

resource storageAccounts_bluecorpazstorage_name_default_BluecorpProcessedOrders 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: Microsoft_Storage_storageAccounts_tableServices_storageAccounts_bluecorpazstorage_name_default
  name: 'BluecorpProcessedOrders'
  properties: {}
}
