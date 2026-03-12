import type { AttackGraphResponse, DataLakeDocument, WarehouseIOCDocument } from '@/lib/analytics/types';
import { ANALYTICS_TIMEZONE, getCountry, getSectorInfo } from '@/lib/analytics/shared';
import type { GraphData, GraphLink, GraphNode, GraphNodeType } from '@/lib/types/graph-types';
import { DEFAULT_NODE_COLORS } from '@/lib/types/graph-types';

type GraphMode = 'with_actors' | 'with_entities' | 'all';

interface MergedIOC {
    warehouse: WarehouseIOCDocument;
    datalake: DataLakeDocument[];
}

function makeKey(iocType: string, iocValue: string): string {
    return `${iocType.toLowerCase()}::${iocValue}`;
}

function addNode(
    nodes: Map<string, GraphNode>,
    id: string,
    label: string,
    type: GraphNodeType,
    subType?: string,
    metadata?: Record<string, unknown>
) {
    if (!nodes.has(id)) {
        nodes.set(id, {
            id,
            label,
            type,
            subType,
            size: type === 'ioc' ? 12 : 10,
            color: DEFAULT_NODE_COLORS[type],
            metadata
        });
    }
}

function addLink(
    links: GraphLink[],
    seen: Set<string>,
    source: string,
    target: string,
    type: GraphLink['type'],
    label: string
) {
    const key = `${source}|${target}|${type}`;
    if (!seen.has(key)) {
        seen.add(key);
        links.push({ source, target, type, label });
    }
}

function mergeDocuments(warehouseDocs: WarehouseIOCDocument[], datalakeDocs: DataLakeDocument[]): MergedIOC[] {
    const datalakeMap = new Map<string, DataLakeDocument[]>();
    for (const doc of datalakeDocs) {
        const key = makeKey(doc.ioc_type, doc.ioc_value);
        const current = datalakeMap.get(key);
        if (current) {
            current.push(doc);
        } else {
            datalakeMap.set(key, [doc]);
        }
    }

    return warehouseDocs.map((warehouse) => ({
        warehouse,
        datalake: datalakeMap.get(makeKey(warehouse.ioc_type, warehouse.ioc_value)) || []
    }));
}

function shouldInclude(doc: MergedIOC, mode: GraphMode): boolean {
    if (mode === 'all') {
        return true;
    }

    const actorCount = doc.warehouse.ai_threat_actors?.length || 0;
    if (mode === 'with_actors') {
        return actorCount > 0;
    }

    const hasMalware = doc.datalake.some((item) => (item.enrichment?.related_entities?.malware_family || []).length > 0);
    const hasInfrastructure = doc.datalake.some((item) =>
        Boolean(item.asn_data?.org || item.asn_data?.asn || item.whois?.registrant_email || item.whois?.name_server || item.whois?.name_servers?.length)
    );
    const hasCountry = doc.datalake.some((item) => Boolean(getCountry(item))) || Boolean(getCountry(doc.warehouse));
    const hasCampaign = doc.datalake.some((item) =>
        Boolean(item.cluster_label) || (item.enrichment?.related_entities?.campaign || []).length > 0
    );

    return actorCount > 0 || hasMalware || hasInfrastructure || hasCountry || hasCampaign;
}

export function buildAttackGraphResponse(
    warehouseDocs: WarehouseIOCDocument[],
    datalakeDocs: DataLakeDocument[],
    mode: GraphMode = 'with_actors'
): AttackGraphResponse {
    const mergedDocs = mergeDocuments(warehouseDocs, datalakeDocs).filter((doc) => shouldInclude(doc, mode));

    const nodes = new Map<string, GraphNode>();
    const links: GraphLink[] = [];
    const seenLinks = new Set<string>();

    for (const entry of mergedDocs) {
        const { warehouse, datalake } = entry;
        const iocId = `ioc:${warehouse.ioc_type}:${warehouse.ioc_value}`;
        addNode(nodes, iocId, warehouse.ioc_value, 'ioc', warehouse.ioc_type, {
            iocType: warehouse.ioc_type,
            riskScore: warehouse.ai_risk_score,
            severity: warehouse.ai_severity
        });

        for (const actor of warehouse.ai_threat_actors || []) {
            const actorId = `actor:${actor.toLowerCase().replace(/\s+/g, '_')}`;
            addNode(nodes, actorId, actor, 'threat_actor');
            addLink(links, seenLinks, iocId, actorId, 'attributed_to', 'attributed to');
        }

        for (const threatType of warehouse.ai_threat_types || []) {
            const typeId = `type:${threatType.toLowerCase().replace(/\s+/g, '_')}`;
            addNode(nodes, typeId, threatType, 'threat_type');
            addLink(links, seenLinks, iocId, typeId, 'classified_as', 'classified as');
        }

        const sectorInfo = getSectorInfo(warehouse);
        if (sectorInfo.sector !== 'general') {
            const sectorId = `sector:${sectorInfo.sector}`;
            addNode(nodes, sectorId, sectorInfo.sector_name_th, 'sector', sectorInfo.sector);
            addLink(links, seenLinks, iocId, sectorId, 'targets', 'targets');
        }

        const country = datalake.map(getCountry).find(Boolean) || getCountry(warehouse);
        if (country) {
            const countryId = `country:${country.toLowerCase()}`;
            addNode(nodes, countryId, country, 'country');
            addLink(links, seenLinks, iocId, countryId, 'located_in', 'located in');
        }

        for (const dataLakeDoc of datalake) {
            for (const malware of dataLakeDoc.enrichment?.related_entities?.malware_family || []) {
                const malwareId = `malware:${malware.toLowerCase().replace(/\s+/g, '_')}`;
                addNode(nodes, malwareId, malware, 'malware');
                addLink(links, seenLinks, iocId, malwareId, 'uses_malware', 'uses malware');
            }

            const infrastructureValues = [
                dataLakeDoc.asn_data?.org,
                dataLakeDoc.asn_data?.asn ? `ASN ${dataLakeDoc.asn_data.asn}` : null,
                dataLakeDoc.whois?.registrant_email,
                ...(Array.isArray(dataLakeDoc.whois?.name_servers) ? dataLakeDoc.whois?.name_servers : []),
                ...(typeof dataLakeDoc.whois?.name_server === 'string' ? [dataLakeDoc.whois?.name_server] : [])
            ].filter(Boolean) as string[];

            for (const infra of infrastructureValues) {
                const infraId = `infra:${infra.toLowerCase().replace(/\s+/g, '_')}`;
                addNode(nodes, infraId, infra, 'infrastructure');
                addLink(links, seenLinks, iocId, infraId, 'shares_infrastructure', 'shares infrastructure');
            }

            const campaignCandidates = [
                ...(dataLakeDoc.enrichment?.related_entities?.campaign || []).map((campaign) => String(campaign)),
                ...(dataLakeDoc.cluster_label !== undefined && dataLakeDoc.cluster_label !== null
                    ? [`cluster_${dataLakeDoc.cluster_label}`]
                    : [])
            ];

            for (const campaign of campaignCandidates) {
                const campaignId = `campaign:${campaign.toLowerCase().replace(/\s+/g, '_')}`;
                addNode(nodes, campaignId, campaign, 'campaign');
                addLink(links, seenLinks, iocId, campaignId, 'same_campaign', 'same campaign');
            }
        }
    }

    const data: GraphData = {
        nodes: Array.from(nodes.values()),
        links
    };

    const countType = (type: GraphNodeType) => data.nodes.filter((node) => node.type === type).length;

    return {
        generated_at: new Date().toISOString(),
        timezone: ANALYTICS_TIMEZONE,
        stats: {
            iocs: countType('ioc'),
            actors: countType('threat_actor'),
            threat_types: countType('threat_type'),
            sectors: countType('sector'),
            countries: countType('country'),
            infrastructures: countType('infrastructure'),
            campaigns: countType('campaign'),
            links: data.links.length
        },
        capabilities: {
            campaigns: countType('campaign') > 0,
            infrastructure: countType('infrastructure') > 0,
            malware: countType('malware') > 0,
            whois: datalakeDocs.some((doc) => Boolean(doc.whois?.registrant_email || doc.whois?.name_server || doc.whois?.name_servers?.length)),
            asn: datalakeDocs.some((doc) => Boolean(doc.asn_data?.asn || doc.asn_data?.org)),
            countries: countType('country') > 0
        },
        data
    };
}
