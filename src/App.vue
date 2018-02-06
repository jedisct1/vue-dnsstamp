<template>
  <div id="app">
    <h1>DNS stamp calculator</h1>
    <DNSStamp/>
    <footer>
      <a href="https://github.com/jedisct1/dnscrypt-proxy/wiki/stamps">DNS stamps</a> specification
      –
      <a href="https://github.com/jedisct1/vue-dnsstamp">source code</a> of this VueJS component
    </footer>
  </div>
</template>

<script>
import DNSStamp from "./components/DNSStamp";

export default {
  name: "App",
  components: {
    DNSStamp
  }
};
</script>

<style>
#app {
  font-family: "Avenir", Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
footer {
  margin-top: 4em;
}
</style>
