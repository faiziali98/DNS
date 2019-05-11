"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse
import random
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

CACHE = {}

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 19 March 2018
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


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)

    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []

    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": name})
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []

    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []

    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []

    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def findip(name):
    """
    This Function finds the ip from the nameserver
    """
    target_name = dns.name.from_text(name)
    response = lookup(target_name, dns.rdatatype.A)
    for answers in response.answer:
        for answer in answers:
            if answer.rdtype == 1:
                return str(answer)


def look_in_add_auth(res, target_name, qtype, DONE, split):
    """
    This Function looks up in additional or authenticate section
    """
    if (res.additional):
        for additional in res.additional:
            for ips in additional:
                if (ips.rdtype == 1):
                    res = lookup_rec(str(ips), target_name,
                                     qtype, DONE, split)
                    if (res):
                        return res
    elif (res.authority):
        for authority in res.authority:
            for ns in authority:
                res = lookup_rec(str(findip(str(ns))),
                                 target_name, qtype, DONE, split)
                if (res):
                    return res


def lookup_rec(ip, target_name, qtype, DONE, split) -> dns.message.Message:
    """
    This Function is recursive lookup
    """
    global CACHE
    part = split.pop()+"."

    if (not (ip in DONE)):
        DONE.append(ip)

        if ((str(target_name), ip) in CACHE.keys()):
            # if already found from this IP directly return answer
            return look_in_add_auth(CACHE[(str(target_name), ip)],
                                    target_name, qtype, DONE, split)
        elif ((part, ip) in CACHE.keys()):
            # sophisticated caching
            return look_in_add_auth(CACHE[(part, ip)], target_name,
                                    qtype, DONE, split)
        else:
            try:
                outbound_query = dns.message.make_query(target_name, qtype)
                res = dns.query.udp(outbound_query, ip, 3)

                if (res.answer):
                    return res
                elif (res.authority[0].rdtype == 6):
                    return res
                else:
                    for x in DONE:
                        CACHE[(str(res.authority[0].name), x)] = res
                    return look_in_add_auth(res, target_name,
                                            qtype, DONE, split)
            except:
                return


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """
    global CACHE
    DONE = []
    split = str(target_name).split(".")
    split = [split.pop()] + split

    if ((target_name, qtype) in CACHE.keys()):
        return CACHE[(target_name, qtype)]
    else:
        RS = list(ROOT_SERVERS)
        # random.shuffle(RS) #To randomly select from root servers
        for ip in RS:
            response = lookup_rec(ip, target_name, qtype, DONE, split)
            if (response):
                if (response.answer):
                    if (response.answer[0].rdtype != qtype):
                        response = lookup(str(response.answer[0][0]), qtype)
                CACHE[(target_name, qtype)] = response
                return response


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()

    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))

if __name__ == "__main__":
    main()
