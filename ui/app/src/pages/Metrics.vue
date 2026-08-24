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
      <q-spinner-hourglass v-if="loading" color="grey" size="4em" />
      <iframe v-else-if="!error" class="iframe-container" src="/api/grafana/?orgId=1&refresh=5s&kiosk=tv" />
      <div v-else class="error-container">
        <q-icon name="warning" class="text-red" style="font-size: 4rem;" />
        Unable to load metrics
      </div>
    </div>
  </q-page>
</template>

<script>
export default {
  name: 'Metrics',

  data () {
    return {
      loading: true,
      error: false
    }
  },

  methods: {
    async loadGrafana () {
      try {
        await this.$axios.get('/api/grafana/api/health')
      } catch (err) {
        this.error = true
        this.$root.$emit('notify-error', err)
      } finally {
        this.loading = false
      }
    }
  },

  mounted () {
    this.loadGrafana()
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

.error-container {
  margin: auto;
  text-align: center;
}
</style>
