"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse
import ipaddress

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.rrset

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

TIMEOUT = 3
MAX_DEPTH = 30

# Cache completed DNS lookups.
LOOKUP_CACHE = {}

# Cache DNS referrals and nameservers for zones.
ZONE_CACHE = {".": list(ROOT_SERVERS)}

# Cache IPv4 addresses of nameservers.
NS_CACHE = {}

# Cache individual DNS server responses.
QUERY_CACHE = {}


def empty_response(name, qtype):
    """Create an empty DNS response."""
    query = dns.message.make_query(name, qtype)
    return dns.message.make_response(query)


def valid_ipv4(address):
    """Return True if an address is IPv4."""
    try:
        return ipaddress.ip_address(str(address)).version == 4
    except (ValueError, TypeError):
        return False


def unique_addresses(addresses):
    """Remove duplicate and invalid IPv4 addresses."""
    result = []
    seen = set()

    for address in addresses:
        address = str(address)

        if valid_ipv4(address) and address not in seen:
            seen.add(address)
            result.append(address)

    return result


def query_server(server, name, qtype):
    """
    Send a non-recursive DNS query to one server.
    Every query has a timeout of 3 seconds.
    """
    if not valid_ipv4(server):
        return None

    key = (str(server), name.to_text().lower(), int(qtype))

    if key in QUERY_CACHE:
        return QUERY_CACHE[key]

    # Record the attempt so failed servers are not retried.
    QUERY_CACHE[key] = None

    try:
        query = dns.message.make_query(name, qtype)

        # Disable recursion.
        query.flags &= ~dns.flags.RD

        response = dns.query.udp(
            query,
            str(server),
            timeout=TIMEOUT
        )

        # Retry over TCP only if the UDP response is truncated.
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(
                query,
                str(server),
                timeout=TIMEOUT
            )

        if response.rcode() in (
            dns.rcode.NOERROR,
            dns.rcode.NXDOMAIN
        ):
            QUERY_CACHE[key] = response
            return response

    except Exception:
        pass

    return None


def get_cached_servers(name):
    """
    Find the most specific cached DNS zone containing name.
    """
    current = name

    while True:
        key = current.to_text().lower()

        if key in ZONE_CACHE and ZONE_CACHE[key]:
            return list(ZONE_CACHE[key])

        if current == dns.name.root:
            break

        current = current.parent()

    return list(ROOT_SERVERS)


def get_answer_records(response, qtype):
    """Find answer records matching the requested type."""
    records = []

    for rrset in response.answer:
        if rrset.rdtype == qtype:
            records.append(rrset)

    return records


def get_cname_records(response):
    """Extract CNAME records from a DNS response."""
    records = []

    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            records.append(rrset)

    return records


def get_referral(response, target_name):
    """
    Extract the most specific NS referral that contains
    the requested domain.
    """
    referrals = []

    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NS:
            continue

        try:
            if target_name.is_subdomain(rrset.name):
                referrals.append(rrset)
        except Exception:
            continue

    if not referrals:
        return None

    return max(
        referrals,
        key=lambda rrset: len(rrset.name.labels)
    )


def get_glue(response, nameservers):
    """
    Extract IPv4 glue records from the Additional section.
    """
    addresses = []

    ns_names = {
        ns.to_text().lower()
        for ns in nameservers
    }

    for rrset in response.additional:
        if rrset.rdtype != dns.rdatatype.A:
            continue

        if rrset.name.to_text().lower() not in ns_names:
            continue

        for record in rrset:
            address = str(record)

            if valid_ipv4(address):
                addresses.append(address)

    return unique_addresses(addresses)


def resolve_nameserver(name, depth, active):
    """
    Resolve an NS hostname to IPv4 addresses.

    This handles unglued nameservers, where the parent
    DNS server does not provide an Additional A record.
    """
    key = name.to_text().lower()

    if key in NS_CACHE:
        return list(NS_CACHE[key])

    if depth >= MAX_DEPTH or key in active:
        return []

    response = iterative_lookup(
        name,
        dns.rdatatype.A,
        depth + 1,
        active
    )

    addresses = []

    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for record in rrset:
                address = str(record)

                if valid_ipv4(address):
                    addresses.append(address)

    addresses = unique_addresses(addresses)

    if addresses:
        NS_CACHE[key] = addresses

    return addresses


def iterative_lookup(target_name, qtype, depth=0, active=None):
    """
    Perform iterative DNS resolution.

    Begin at a root server or the closest cached zone,
    follow referrals, and resolve CNAMEs when needed.
    """
    if active is None:
        active = set()

    key = (
        target_name.to_text().lower(),
        int(qtype)
    )

    if key in LOOKUP_CACHE:
        return LOOKUP_CACHE[key]

    if depth >= MAX_DEPTH or key in active:
        return empty_response(target_name, qtype)

    active = set(active)
    active.add(key)

    servers = get_cached_servers(target_name)
    tried = set()
    visited_zones = set()
    last_response = None

    while servers:
        next_servers = []
        referrals = []
        referral_zone = None

        for server in servers:
            if server in tried:
                continue

            tried.add(server)

            response = query_server(
                server,
                target_name,
                qtype
            )

            if response is None:
                continue

            last_response = response

            if response.rcode() == dns.rcode.NXDOMAIN:
                LOOKUP_CACHE[key] = response
                return response

            answers = get_answer_records(response, qtype)

            if answers:
                LOOKUP_CACHE[key] = response
                return response

            cnames = get_cname_records(response)

            if cnames:
                # A CNAME query is already answered.
                if qtype == dns.rdatatype.CNAME:
                    LOOKUP_CACHE[key] = response
                    return response

                cname = cnames[-1][0].target

                if cname == target_name:
                    continue

                cname_response = iterative_lookup(
                    cname,
                    qtype,
                    depth + 1,
                    active
                )

                combined = empty_response(
                    target_name,
                    qtype
                )

                for rrset in response.answer:
                    combined.answer.append(rrset)

                for rrset in cname_response.answer:
                    if rrset not in combined.answer:
                        combined.answer.append(rrset)

                LOOKUP_CACHE[key] = combined
                return combined

            referral = get_referral(
                response,
                target_name
            )

            if referral is not None:
                zone = referral.name.to_text().lower()

                # Only accept a referral if it moves
                # closer to the requested domain.
                if zone in visited_zones:
                    continue

                ns_names = [
                    record.target
                    for record in referral
                ]

                glue = get_glue(
                    response,
                    ns_names
                )

                referrals.append(
                    (zone, ns_names, glue)
                )

                if (
                    referral_zone is None
                    or len(referral.name.labels)
                    > len(dns.name.from_text(
                        referral_zone
                    ).labels)
                ):
                    referral_zone = zone

                continue

            # An authoritative NOERROR response with no
            # matching records is a valid negative answer.
            if response.flags & dns.flags.AA:
                LOOKUP_CACHE[key] = response
                return response

        if not referrals:
            break

        # Prefer the most specific referral.
        selected = [
            item for item in referrals
            if item[0] == referral_zone
        ]

        for zone, ns_names, glue in selected:
            next_servers.extend(glue)

            # Resolve nameservers missing IPv4 glue.
            glued_names = set()

            for response_server in servers:
                response = query_server(
                    response_server,
                    target_name,
                    qtype
                )

                if response is None:
                    continue

                for rrset in response.additional:
                    if rrset.rdtype == dns.rdatatype.A:
                        glued_names.add(
                            rrset.name.to_text().lower()
                        )

            for ns_name in ns_names:
                ns_key = ns_name.to_text().lower()

                if ns_key in glued_names:
                    continue

                addresses = resolve_nameserver(
                    ns_name,
                    depth + 1,
                    active
                )

                next_servers.extend(addresses)

        next_servers = unique_addresses(next_servers)

        if next_servers:
            ZONE_CACHE[referral_zone] = next_servers
            visited_zones.add(referral_zone)

        servers = [
            server for server in next_servers
            if server not in tried
        ]

    if last_response is not None:
        LOOKUP_CACHE[key] = last_response
        return last_response

    return empty_response(target_name, qtype)


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    Resolve DNS records without using a recursive resolver.
    """
    try:
        if isinstance(target_name, str):
            target_name = dns.name.from_text(target_name)

        return iterative_lookup(
            target_name,
            qtype
        )

    except Exception:
        return empty_response(target_name, qtype)


def collect_results(name: str) -> dict:
    """
    Parse DNS answers into the format required by
    print_results().
    """
    full_response = {
        "CNAME": [],
        "A": [],
        "AAAA": [],
        "MX": []
    }

    try:
        target_name = dns.name.from_text(name)

        # CNAME lookup
        response = lookup(
            target_name,
            dns.rdatatype.CNAME
        )

        cnames = []
        seen_cnames = set()

        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.CNAME:
                continue

            for record in rrset:
                alias = rrset.name.to_text()
                destination = record.target.to_text()

                key = (alias, destination)

                if key not in seen_cnames:
                    seen_cnames.add(key)
                    cnames.append({
                        "alias": alias,
                        "name": destination
                    })

        # A lookup
        response_a = lookup(
            target_name,
            dns.rdatatype.A
        )

        arecords = []

        for rrset in response_a.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for record in rrset:
                    alias = rrset.name.to_text()
                    destination = record.target.to_text()
                    key = (alias, destination)

                    if key not in seen_cnames:
                        seen_cnames.add(key)
                        cnames.append({
                            "alias": alias,
                            "name": destination
                        })

            if rrset.rdtype == dns.rdatatype.A:
                for record in rrset:
                    arecords.append({
                        "name": rrset.name,
                        "address": str(record)
                    })

        # AAAA lookup
        response_aaaa = lookup(
            target_name,
            dns.rdatatype.AAAA
        )

        aaaarecords = []

        for rrset in response_aaaa.answer:
            if rrset.rdtype == dns.rdatatype.AAAA:
                for record in rrset:
                    aaaarecords.append({
                        "name": rrset.name,
                        "address": str(record)
                    })

        # MX lookup
        response_mx = lookup(
            target_name,
            dns.rdatatype.MX
        )

        mxrecords = []

        for rrset in response_mx.answer:
            if rrset.rdtype == dns.rdatatype.MX:
                for record in rrset:
                    mxrecords.append({
                        "name": rrset.name,
                        "preference": record.preference,
                        "exchange": str(record.exchange)
                    })

        full_response["CNAME"] = cnames
        full_response["A"] = arecords
        full_response["AAAA"] = aaaarecords
        full_response["MX"] = mxrecords

    except Exception:
        pass

    return full_response


def print_results(results: dict) -> None:
    """
    Print DNS records using the host-style output format.
    """
    found = False

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))
            found = True

    if not found:
        print("No DNS records found or resolution failed.")


def main():
    """
    Resolve one or more domains from command-line arguments.
    """
    argument_parser = argparse.ArgumentParser()

    argument_parser.add_argument(
        "name",
        nargs="+",
        help="DNS name(s) to look up"
    )

    argument_parser.add_argument(
        "-v",
        "--verbose",
        help="increase output verbosity",
        action="store_true"
    )

    program_args = argument_parser.parse_args()

    for a_domain_name in program_args.name:
        try:
            results = collect_results(a_domain_name)
            print_results(results)
        except Exception:
            print(
                "DNS resolution failed for "
                + a_domain_name
            )


if __name__ == "__main__":
    main()
