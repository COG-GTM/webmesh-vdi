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
      <iframe v-if="ready" class="iframe-container" src="/api/grafana/?orgId=1&refresh=5s&kiosk=tv" />
    </div>
  </q-page>
</template>

<script>
// The dashboard is authenticated by the session cookie issued with the access
// token, and its requests do not go through axios, so nothing renews the
// session while the page sits open. Renew it here instead, otherwise the
// dashboard starts returning forbidden once the access token expires.
const fallbackDelay = 5 * 60 * 1000
const minDelay = 30 * 1000

export default {
  name: 'Metrics',

  data () {
    return {
      // The iframe request cannot be retried, so it is only made once the
      // session cookie is known to be current.
      ready: false
    }
  },

  async mounted () {
    await this.refresh()
    this.ready = true
  },

  beforeDestroy () {
    this.stopped = true
    clearTimeout(this.timer)
  },

  methods: {
    async refresh () {
      clearTimeout(this.timer)
      if (!this.$userStore.getters.renewable) {
        return
      }
      try {
        await this.$userStore.dispatch('refreshToken', { background: true })
      } catch (err) {
        console.error(err)
      }
      // The page may have been left while the renewal was in flight, in which
      // case beforeDestroy already cleared a timer that did not exist yet.
      if (this.stopped) {
        return
      }
      this.timer = setTimeout(this.refresh, this.nextDelay())
    },

    // nextDelay renews halfway through the remaining lifetime of the token, so
    // that a token duration shorter than the fallback still works.
    nextDelay () {
      const expiresAt = this.$userStore.getters.expiresAt
      if (!expiresAt) {
        return fallbackDelay
      }
      return Math.max((expiresAt * 1000 - Date.now()) / 2, minDelay)
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
