<template>
    <form>
      <fieldset>
        <label>Protocol:
          <select v-model="proto">
            <option value="DNSCrypt">DNSCrypt</option>
            <option value="DoH">DNS-over-HTTP/2</option>
          </select>
        </label>
        <label>DNSSEC
          <input type="checkbox"  v-model="dnssec"/>
        </label>
        <label>No logs
          <input type="checkbox" v-model="nolog"/>
        </label>
        <label>No filter
          <input type="checkbox" v-model="nofilter"/>
        </label>
      </fieldset>
      <fieldset class="protoprops">
        <label>IP address:
          <input v-model="addr"/>
        </label>
        <span v-if="proto==='DNSCrypt'">
          <label>Provider public key:
            <input  v-model="pk"/>
          </label>
          <label>Provider name:
            <input v-model="providerName"/>
          </label>
        </span>
        <span v-if="proto==='DoH'">
          <label>Host name (vhost+SNI) and optional port number:
            <input v-model="hostName"/>
          </label>
          <label>Certificate hash (SHA256):
            <input v-model="hash"/>
          </label>
          <label>Path:
            <input v-model="path"/>
          </label>
        </span>
      </fieldset>
      <fieldset class="protoprops">
        <label>Stamp:
          <input :value="stamp" @input="stampUpdated"/>
        </label>
      </fieldset>
    </form>
</template>

<script>
const URLSafeBase64 = require("urlsafe-base64");

export default {
  name: "DNSStamp",
  data() {
    return {
      proto: "DNSCrypt",
      dnssec: true,
      nolog: true,
      nofilter: true,
      addr: "",
      pk: "",
      providerName: "2.dnscrypt-cert.",
      hostName: "",
      hash: "",
      path: "/dns-query"
    };
  },
  methods: {
    stampUpdated(e) {
      let stamp = e.target.value;
      if (stamp.substr(0, 7) !== "sdns://") {
        return;
      }
      let bin = URLSafeBase64.decode(stamp.substr(7));
      if (bin[0] === 0x01) {
        this.proto = "DNSCrypt";
      } else if (bin[0] === 0x02) {
        this.proto = "DoH";
      } else {
        return;
      }
      let props = bin[1];
      this.dnssec = !!((props >> 0) & 1);
      this.nolog = !!((props >> 1) & 1);
      this.nofilter = !!((props >> 2) & 1);
      let i = 9;
      let addrLen = bin[i++];
      this.addr = bin.slice(i, i + addrLen).toString("utf-8");
      i += addrLen;

      const dnscryptStamp = () => {
        let pkLen = bin[i++];
        this.pk = bin.slice(i, i + pkLen).toString("hex");
        i += pkLen;
        let providerNameLen = bin[i++];
        this.providerName = bin.slice(i, i + providerNameLen).toString("utf-8");
      };

      const dohStamp = () => {
        let hashLen = bin[i++];
        this.hash = bin.slice(i, i + hashLen).toString("hex");
        i += hashLen;
        let hostNameLen = bin[i++];
        this.hostName = bin.slice(i, i + hostNameLen).toString("utf-8");
        i += hostNameLen;
        let pathLen = bin[i++];
        this.path = bin.slice(i, i + pathLen).toString("utf-8");
      };

      if (this.proto === "DNSCrypt") {
        dnscryptStamp();
      } else if (this.proto === "DoH") {
        dohStamp();
      }
    }
  },
  computed: {
    stamp: function() {
      let props = (this.dnssec << 0) | (this.nolog << 1) | (this.nofilter << 2);
      let addr = this.addr.split("").map(c => c.charCodeAt());

      const dnscryptStamp = () => {
        let v = [0x01, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        v.push(addr.length, ...addr);
        let pk = Buffer.from(this.pk.replace(/[: \t]/g, ""), "hex");
        v.push(pk.length, ...pk);
        let providerName = this.providerName.split("").map(c => c.charCodeAt());
        v.push(providerName.length, ...providerName);
        return `sdns://${URLSafeBase64.encode(Buffer(v))}`;
      };

      const dohStamp = () => {
        let v = [0x02, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        v.push(addr.length, ...addr);
        let hash = Buffer.from(this.hash.replace(/[: \t]/g, ""), "hex");
        v.push(hash.length, ...hash);
        let hostName = this.hostName.split("").map(c => c.charCodeAt());
        v.push(hostName.length, ...hostName);
        let path = this.path.split("").map(c => c.charCodeAt());
        v.push(path.length, ...path);
        return `sdns://${URLSafeBase64.encode(Buffer(v))}`;
      };

      if (this.proto === "DNSCrypt") {
        return dnscryptStamp();
      } else {
        return dohStamp();
      }
    }
  }
};
</script>

<style scoped>
.protoprops label {
  display: block;
}
.protoprops input {
  display: block;
  width: 80%;
  margin: auto;
}
</style>
