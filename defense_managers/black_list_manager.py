from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from configuration import SDN_CONTROLLER_APP_KEY

url1 = '/add_chains'
url2 = '/add_classifier_rules'
url3 = '/create_blacklist_rules'
BASE_POLICY = 100
BLACKLIST_IP_POLICY = 101
WHITELIST_IP_POLICY = 102


class BlackListManager(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(BlackListManager, self).__init__(req, link, data, **config)
        self.sdn_controller_app = data[SDN_CONTROLLER_APP_KEY]
        self.black_list = set()


    @route('add_classifier_rules', url2, methods=['POST'])
    def create_classifier_rules(self, req, **kwargs):
        try:
            input = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        app = self.sdn_controller_app


        for new_entry in input:
            dpid = new_entry["dpid"]
            out_port = new_entry["classifier_port"]
            input_port = new_entry["client_port"]
            table_id = 0

            dp = int("0x" + dpid, 16)
            datapath = app.switches.get(dp)
            parser = datapath.ofproto_parser



            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_type_nxm=0x0800, ip_proto=6, in_port=input_port)
            app.add_flow(datapath, 0x1, match, actions, table_id=table_id,  cookie=0x66666)

            match = parser.OFPMatch(eth_type_nxm=0x0800, ip_proto=0x11) # UDP
            instruction = [
                parser.OFPInstructionActions(datapath.ofproto.OFPIT_CLEAR_ACTIONS, [])
            ]
            app.add_flow(datapath, 0x1, match, [], table_id=0, instruction=instruction ,cookie=0x66667)




    @route('create_blacklist_rules', url3, methods=['POST'])
    def create_blacklist_rules(self, req, **kwargs):
        try:
            input = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        app = self.sdn_controller_app


        for new_entry in input:
            table_id = BLACKLIST_IP_POLICY
            switches = app.switches
            for sw in switches:
                datapath = app.switches.get(sw)

                priority = 0xFF
                cookie=0x321321
                metadata      = 0x1
                metadata_mask = 0x1
                parser = datapath.ofproto_parser


                instruction = [
                    parser.OFPInstructionGotoTable(101),
                ]
                match = parser.OFPMatch()
                mod = parser.OFPFlowMod(datapath=datapath,
                                        priority=priority + 1, match=match,
                                        instructions=instruction, table_id=0, cookie=cookie)
                datapath.send_msg(mod)


                instruction = [
                    parser.OFPInstructionActions(datapath.ofproto.OFPIT_CLEAR_ACTIONS, []),
                    parser.OFPInstructionWriteMetadata(metadata=metadata, metadata_mask=metadata_mask),
                    parser.OFPInstructionGotoTable(102),
                ]
                actions = []
                match = parser.OFPMatch(eth_type_nxm=0x0800, ipv4_src=new_entry)

                mod = parser.OFPFlowMod(datapath=datapath,
                                        priority=priority, match=match,
                                        instructions=instruction, table_id=table_id, cookie=cookie)
                datapath.send_msg(mod)



                instruction = [
                    parser.OFPInstructionGotoTable(WHITELIST_IP_POLICY),
                ]
                match = parser.OFPMatch()
                mod = parser.OFPFlowMod(datapath=datapath,
                                        priority=0, match=match,
                                        instructions=instruction, table_id=BLACKLIST_IP_POLICY, cookie=cookie)
                datapath.send_msg(mod)


                #app.add_flow(datapath, 0xFF, match, actions, table_id=table_id,  cookie=0x321321)

                #match = parser.OFPMatch(eth_type_nxm=0x0800, ip_proto=0x11) # UDP

                #app.add_flow(datapath, 0x1, match, [], table_id=0, instruction=instruction ,cookie=0x66667)

        self.create_whitelist_rules(req)

    def create_whitelist_rules(self, req, **kwargs):
        try:
            input = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        app = self.sdn_controller_app


        for new_entry in input:
            table_id = WHITELIST_IP_POLICY
            switches = app.switches
            for sw in switches:
                datapath = app.switches.get(sw)

                priority = 0xFF
                cookie=0x321321
                metadata      = 0x2
                metadata_mask = 0x2
                parser = datapath.ofproto_parser

                ofproto = datapath.ofproto

                actions = [parser.OFPActionOutput(1)]
                instruction = [
                    parser.OFPInstructionWriteMetadata(metadata=metadata, metadata_mask=metadata_mask),
                    parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)
                ]
                match = parser.OFPMatch(eth_type_nxm=0x0800, ipv4_src=new_entry, metadata=(0x1,0x1))

                mod = parser.OFPFlowMod(datapath=datapath,
                                        priority=priority, match=match,
                                        instructions=instruction, table_id=table_id, cookie=cookie)
                datapath.send_msg(mod)
                #app.add_flow(datapath, 0xFF, match, actions, table_id=table_id,  cookie=0x321321)

                #match = parser.OFPMatch(eth_type_nxm=0x0800, ip_proto=0x11) # UDP

                #app.add_flow(datapath, 0x1, match, [], table_id=0, instruction=instruction ,cookie=0x66667)
                instruction = [
                    parser.OFPInstructionActions(datapath.ofproto.OFPIT_CLEAR_ACTIONS, [])
                ]
                match = parser.OFPMatch()
                mod = parser.OFPFlowMod(datapath=datapath,
                                        priority=0, match=match,
                                        instructions=instruction, table_id=WHITELIST_IP_POLICY, cookie=cookie)
                datapath.send_msg(mod)
