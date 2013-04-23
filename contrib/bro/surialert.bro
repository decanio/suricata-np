@load frameworks/communication/listen
@load types

# Let's make sure we use the same port no matter whether we use encryption or not:
redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
redef Communication::listen_ssl = F;

# Set the SSL certificates being used to something real if you are using encryption.
#redef ssl_ca_certificate   = "<path>/ca_cert.pem";
#redef ssl_private_key      = "<path>/bro.pem";

global alert_log = open_log_file("alerts");

#global alert: event(msg: string, content: string);

redef Communication::nodes += {
	["suricata"] = [$host = 127.0.0.1, $class="suricata", $events = /suricata_alert/, $connect=F, $ssl=F]
};

event suricata_alert(id: suricata::PacketID,
                     alert: suricata::AlertData,
                     msg: string,
                     content: string)
        {
        print alert_log, fmt("%f [%d:%d:%d] %s [Classification: %s] [Priority: %d] %s:%s -> %s:%d",
                            alert$ts,
                            alert$generator_id,
                            alert$signature_id,
                            alert$signature_revision,
                            msg,
                            alert$classification,
                            alert$priority_id,
                            id$src_ip, id$src_p,
                            id$dst_ip, id$dst_p);
        }
