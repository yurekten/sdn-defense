

def delete_flow(datapath, cookie=0, cookie_mask=0xFFFFFFFFFFFFFFFF):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    mod = parser.OFPFlowMod(datapath=datapath,
                            command=ofproto.OFPFC_DELETE,
                            out_port=ofproto.OFPP_ANY,
                            out_group=ofproto.OFPG_ANY,
                            table_id=ofproto.OFPTT_ALL,
                            cookie=cookie,
                            cookie_mask=cookie_mask,
                            )
    datapath.send_msg(mod)