const Host = '13.223.95.66'; // CoC 18.0.5 doesn't like Local IPS, so use Public IP
const Port = '9339';

var base = Process.getModuleByName("libg.so").base;
const libc = Process.getModuleByName("libc.so");
const getaddrinfo = libc.findExportByName('getaddrinfo');
const loadoffset = 0xE97600;
const addr = base.add(loadoffset);
const original = addr.readByteArray(4);

const PepperKiller = {
    init() {
        //try {
            Interceptor.replace(base.add(0xE8EA8C), new NativeCallback(function() {
                console.warn("[+][PepperCrypto::secretbox_open] Skipped decryption");
                return 1;
            }, 'int', []));
        /*}
        catch (e) {
            console.warn("[+] PepperCrypto::secretbox_open is already skipped! ", e)
        }*/
        /*Interceptor.attach(base.add(0xCF47A8), { // Messaging::sendPepperAuthentication
            onEnter(args) {
                this.messaging = args[0];
                const ptr = this.messaging.add(24);
                console.warn("[+][PepperState::State][1] Pepper State Is", ptr.readU32(this.messaging.add(24)));
                ptr.writeU32(this.messaging.add(24), 5);
                args[1] = args[2];
                console.warn("[+][PepperState::State][2] Pepper State Is", ptr.readU32(this.messaging.add(24)));

            },
            onLeave(retval) {
                const ptr = this.messaging.add(24);
                ptr.writeU32(this.messaging.add(24), 5);
                console.warn("[+][PepperState::State][3] Pepper State Is", ptr.readU32(this.messaging.add(24)));
            }
        });*/
        Interceptor.attach(base.add(0xE8F898), function() { // Messaging::encryptAndWrite
            this.context.w0 = this.context.w8; // not tested
            console.warn("[+][PepperCrypto::secretbox_open] Skipped encryption");
        });
    }
}

Interceptor.attach(getaddrinfo, {
    onEnter(args) {
        this.host = Memory.allocUtf8String(Host);
        args[0] = this.host;
        this.port = Memory.allocUtf8String(Port);
        args[1] = this.port;

        // Initialization
        {
            PepperKiller.init()
        }
        
        Memory.protect(addr, 0x1000, 'rwx');
        addr.writeByteArray(original);

        setTimeout(() => {
            addr.writeU8(0xA8);
            addr.add(1).writeU8(0x00);
            addr.add(2).writeU8(0x80);
            addr.add(3).writeU8(0x52);
        }, 1000);
    }

});
