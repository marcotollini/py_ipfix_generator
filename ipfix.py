import sys
from scapy.all import IP,UDP,NetflowHeader,NetflowHeaderV9,NetflowFlowsetV9,NetflowTemplateV9,NetflowTemplateFieldV9,GetNetflowRecordV9,NetflowDataflowsetV9,send


def craft_packet(src_ip, dst_ip, src_port, dest_port):
    header = IP(src=src_ip,dst=dst_ip)/UDP(sport=src_port,dport=dest_port)
    netflow_header = NetflowHeader()/NetflowHeaderV9()

    # Let's first build the template. Those need an ID > 255
    flowset = NetflowFlowsetV9(
        templates=[NetflowTemplateV9(
            template_fields=[
                #https://github.com/secdev/scapy/blob/master/scapy/layers/netflow.py#L257
                NetflowTemplateFieldV9(fieldType=1, fieldLength=4),  # IN_BYTES
                NetflowTemplateFieldV9(fieldType=2, fieldLength=4),  # IN_PKTS
                NetflowTemplateFieldV9(fieldType=4),  # PROTOCOL
                NetflowTemplateFieldV9(fieldType=8),  # IPV4_SRC_ADDR
                NetflowTemplateFieldV9(fieldType=12),  # IPV4_DST_ADDR
                NetflowTemplateFieldV9(fieldType=10),  # INPUT_SNMP
                NetflowTemplateFieldV9(fieldType=14),  # OUTPUT_SNMP
                NetflowTemplateFieldV9(fieldType=16, fieldLength=4),  # SRC_AS
                NetflowTemplateFieldV9(fieldType=17, fieldLength=4),  # DST_AS
                NetflowTemplateFieldV9(fieldType=90, fieldLength=8)  # VPN_ROUTE_DISTINGUISHER
            ],
            templateID=256,
            fieldCount=10)
        ],
        flowSetID=0
    )
    # Let's generate the record class. This will be a Packet class
    # In case you provided several templates in ghe flowset, you will need
    # to pass the template ID as second parameter
    recordClass = GetNetflowRecordV9(flowset)
    # Now lets build the data records
    dataFS = NetflowDataflowsetV9(
        templateID=256,
        records=[ # Some random data.
            recordClass(
                #https://github.com/secdev/scapy/blob/master/scapy/layers/netflow.py#L257
                IN_BYTES=b"\x00\x00\x00\x01",
                IN_PKTS=b"\x00\x00\x00\x01",
                PROTOCOL=6,
                IPV4_SRC_ADDR="1.1.1.1",
                IPV4_DST_ADDR="2.2.2.2",
                INPUT_SNMP=b"\x00\x62",
                OUTPUT_SNMP=b"\x00\x63",
                SRC_AS=65511,
                DST_AS=65512,
                #on tcpdump: 0000270F3B9AC9FF = 0:9999:999999999
                # type 0     0000
                # 9999           270F
                # 999999999          3B9AC9FF
                VPN_ROUTE_DISTINGUISHER=b"\x00\x00\x27\x0f\x3b\x9a\xc9\xff"
            ),
            recordClass(
                IN_BYTES=b"\x00\x00\x00\x01",
                IN_PKTS=b"\x00\x00\x00\x01",
                PROTOCOL=6,
                IPV4_SRC_ADDR="3.3.3.3",
                IPV4_DST_ADDR="4.4.4.4",
                INPUT_SNMP=b"\x00\x62",
                OUTPUT_SNMP=b"\x00\x63",
                SRC_AS=65511,
                DST_AS=65512,
                #on tcpdump: 0000270F3B9AC9FF = 0:9999:999999999
                # type 0     0000
                # 9999           270F
                # 999999999          3B9AC9FF
                VPN_ROUTE_DISTINGUISHER=b"\x00\x00\x27\x0f\x3b\x9a\xc9\xff"
            )
        ],
    )
    pkt = header / netflow_header / flowset / dataFS
    return pkt
