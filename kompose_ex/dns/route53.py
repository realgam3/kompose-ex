import boto3

route53_api = boto3.client('route53')


def change_resource_record_sets(zone_id, name, record, ttl=60):
    return route53_api.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Comment": f"UPSERT CNAME record {name}",
            "Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": name,
                    "Type": "CNAME",
                    "TTL": ttl,
                    "ResourceRecords": [{
                        "Value": record
                    }]
                }
            }]
        }
    )


def update_cname_record(zone_id, name, record, ttl=60):
    res = update_cname_record(zone_id, name, record, ttl=ttl)
    return res


def get_hosted_zones_by_name(name):
    res = route53_api.list_hosted_zones_by_name(DNSName=name) or {}
    hosted_zones = res.get("HostedZones", {})
    if hosted_zones:
        return hosted_zones[0].get("Id", "").split("/")[-1]
