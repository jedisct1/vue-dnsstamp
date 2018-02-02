<template>
  <div id="app">
    <h1>DNS stamp calculator</h1>
    <DNSStamp/>
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
</style>
