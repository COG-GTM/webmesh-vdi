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
      <iframe class="iframe-container" :src="grafanaURL" />
    </div>
  </q-page>
</template>

<script>
// grafana requests do not go through axios, so they cannot trigger the token
// refresh interceptor. Renew on an interval instead, which recomputes the iframe
// source and re-seeds the proxy cookie.
const tokenRefreshInterval = 5 * 60 * 1000

export default {
  name: 'Metrics',

  data () {
    return { refreshTimer: null }
  },

  computed: {
    grafanaURL () {
      const token = encodeURIComponent(this.$userStore.getters.token)
      return `/api/grafana/?orgId=1&refresh=5s&kiosk=tv&token=${token}`
    }
  },

  mounted () {
    this.refreshTimer = setInterval(() => {
      if (this.$userStore.getters.renewable) {
        this.$userStore.dispatch('refreshToken')
      }
    }, tokenRefreshInterval)
  },

  beforeDestroy () {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer)
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
