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
      <iframe v-if="authenticated" class="iframe-container" :src="grafanaURL" />
    </div>
  </q-page>
</template>

<script>
// The dashboards authenticate with a cookie that is kept fresh while the page is
// open, since the session token behind it is short-lived.
const sessionRefreshInterval = 60000

export default {
  name: 'Metrics',
  data () {
    return {
      authenticated: false,
      destroyed: false,
      refreshInterval: null,
      grafanaURL: '/api/grafana/?orgId=1&refresh=5s&kiosk=tv'
    }
  },
  async mounted () {
    await this.setGrafanaSession()
    if (this.destroyed) {
      return
    }
    this.authenticated = true
    this.refreshInterval = setInterval(this.setGrafanaSession, sessionRefreshInterval)
  },
  beforeDestroy () {
    this.destroyed = true
    clearInterval(this.refreshInterval)
  },
  methods: {
    async setGrafanaSession () {
      await this.$axios.post('/api/grafana/session')
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
