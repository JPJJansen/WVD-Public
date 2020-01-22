# WVD-Public

## Log Analytics script
This scripts allows to upload logging data from WVD to a Log Analytics Workspaces. This script can run on a server as schedule task. 
Log information:
- HostPoolName
- SessionHostName
- UserPrincipalName
- CreateTime
- SessionState

Example in Log Analytics:
![alt text](https://raw.githubusercontent.com/JPJJansen/WVD-Public/master/images/LogAnalytics.PNG)

You can use this data for example in Grafana
![alt text](https://raw.githubusercontent.com/JPJJansen/WVD-Public/master/images/Grafana.png)

## Scale script
This scripts allows to scale the WVD envirnoment with peak days and peak hours. This script can run on a server as schedule task. 
