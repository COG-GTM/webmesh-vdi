<!--
Copyright 2020,2021 Avi Zimmerman

This file is part of kvdi.

kvdi is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

kvdi is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with kvdi.  If not, see <https://www.gnu.org/licenses/>.
-->

<template>
  <q-page flex>
    <div class="display-container">
      <iframe v-if="authorized" class="iframe-container" src="/api/grafana/?orgId=1&refresh=5s&kiosk=tv" />
    </div>
  </q-page>
</template>

<script>
export default {
  name: 'Metrics',

  data () {
    return {
      authorized: false,
      renewInterval: null
    }
  },

  computed: {
    token () {
      return this.$userStore.getters.token
    }
  },

  watch: {
    token: 'authorizeGrafana'
  },

  mounted () {
    this.authorizeGrafana()
    // The iframe's requests bypass the axios interceptors that renew an expired
    // token, so the session cookie is refreshed on a timer instead.
    this.renewInterval = setInterval(this.authorizeGrafana, 60000)
  },

  beforeDestroy () {
    clearInterval(this.renewInterval)
  },

  methods: {
    async authorizeGrafana () {
      try {
        await this.$axios.get('/api/grafana/api/health')
        this.authorized = true
      } catch (err) {
        this.authorized = false
        this.$root.$emit('notify-error', err)
      }
    }
  }
}
</script>

<style scoped>
.display-container {
  display: flex;
  width: 100%;
  height: 100vh;
  flex-direction: column;
  background-color: grey;
  overflow: hidden;
}

.iframe-container {
  flex-grow: 1;
  border: none;
  margin: 0;
  padding: 0;
}
</style>
