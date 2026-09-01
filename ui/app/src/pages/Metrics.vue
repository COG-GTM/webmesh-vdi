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
      renewTimeout: null
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
  },

  beforeDestroy () {
    clearTimeout(this.renewTimeout)
  },

  methods: {
    // authorizeGrafana exchanges the session token for the cookie the embedded
    // grafana UI uses to authenticate its own requests.
    async authorizeGrafana () {
      try {
        await this.$axios.get('/api/grafana/api/health')
        this.authorized = true
        this.scheduleRenewal()
      } catch (err) {
        this.authorized = false
        this.$root.$emit('notify-error', err)
      }
    },

    // The iframe's requests bypass the axios interceptor that renews an expired
    // token, so the token is renewed before the cookie it issued expires.
    scheduleRenewal () {
      clearTimeout(this.renewTimeout)
      if (!this.$userStore.getters.renewable) {
        return
      }
      const expiresAt = this.tokenExpiry()
      if (expiresAt === null) {
        return
      }
      const renewIn = Math.max(expiresAt - Date.now() - 30000, 0)
      this.renewTimeout = setTimeout(async () => {
        try {
          await this.$userStore.dispatch('refreshToken')
        } catch (err) {
          this.$root.$emit('notify-error', err)
        }
      }, renewIn)
    },

    tokenExpiry () {
      try {
        const claims = JSON.parse(atob(this.token.split('.')[1]))
        return claims.exp * 1000
      } catch (err) {
        return null
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
