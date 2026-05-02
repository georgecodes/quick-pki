<script setup>
import { computed, onMounted, ref } from 'vue'
import {
  Activity,
  BadgeCheck,
  ClipboardList,
  KeyRound,
  LogOut,
  RefreshCw,
  RotateCw,
  Search,
  ShieldCheck,
  UsersRound
} from 'lucide-vue-next'

const tabs = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'accounts', label: 'Accounts', icon: UsersRound },
  { id: 'orders', label: 'Requests', icon: ClipboardList },
  { id: 'ca', label: 'CA keys', icon: KeyRound }
]

const activeTab = ref('overview')
const config = ref(null)
const loggedIn = ref(false)
const loading = ref(true)
const error = ref('')
const rotating = ref(false)
const query = ref('')
const selectedOrder = ref(null)

const summary = ref({ totals: {}, orderStatuses: {}, challengeStatuses: {} })
const accounts = ref([])
const orders = ref([])
const ca = ref(null)

const filteredAccounts = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return accounts.value
  return accounts.value.filter(account =>
    [account.id, account.keyThumbprint, account.status, ...(account.contact || [])]
      .join(' ')
      .toLowerCase()
      .includes(q)
  )
})

const filteredOrders = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return orders.value
  return orders.value.filter(order =>
    [order.id, order.accountId, order.accountThumbprint, order.status, identifierText(order)]
      .join(' ')
      .toLowerCase()
      .includes(q)
  )
})

const recentOrders = computed(() => orders.value.slice(0, 6))

onMounted(async () => {
  await boot()
})

async function boot() {
  loading.value = true
  error.value = ''
  try {
    config.value = await api('/api/app-config')
    const tokens = await api('/api/tokens')
    loggedIn.value = Boolean(tokens.tokens)
    if (loggedIn.value) {
      await refreshAll()
    }
  } catch (err) {
    error.value = err.message
  } finally {
    loading.value = false
  }
}

async function refreshAll() {
  const [summaryData, accountData, orderData, caData] = await Promise.all([
    api('/api/admin/summary'),
    api('/api/admin/accounts'),
    api('/api/admin/orders'),
    api('/api/admin/ca')
  ])
  summary.value = summaryData
  accounts.value = accountData || []
  orders.value = orderData || []
  ca.value = Object.keys(caData || {}).length ? caData : null
}

async function login() {
  error.value = ''
  try {
    const response = await post('/api/start', {
      issuer: config.value.issuer,
      client_id: config.value.clientId,
      scopes: config.value.scopes,
      flow: 'auth_code',
      use_pkce: true
    })
    window.location.href = response.redirect
  } catch (err) {
    error.value = err.message
  }
}

async function logout() {
  await post('/api/admin/session/logout', {})
  loggedIn.value = false
  selectedOrder.value = null
}

async function rotateCA() {
  rotating.value = true
  error.value = ''
  try {
    ca.value = await post('/api/admin/ca/rotate', {})
    await refreshAll()
  } catch (err) {
    error.value = err.message
  } finally {
    rotating.value = false
  }
}

async function openOrder(order) {
  selectedOrder.value = await api(`/api/admin/orders/${order.id}`)
}

async function api(path) {
  const response = await fetch(path, { headers: { Accept: 'application/json' } })
  return readResponse(response)
}

async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  return readResponse(response)
}

async function readResponse(response) {
  const text = await response.text()
  const value = text ? JSON.parse(text) : {}
  if (!response.ok) {
    throw new Error(value.error || response.statusText)
  }
  return value
}

function statusClass(status) {
  return {
    valid: 'bg-teal-100 text-teal-800 ring-teal-600/20',
    ready: 'bg-sky-100 text-sky-800 ring-sky-600/20',
    pending: 'bg-amber-100 text-amber-900 ring-amber-600/20',
    invalid: 'bg-rose-100 text-rose-800 ring-rose-600/20',
    revoked: 'bg-zinc-200 text-zinc-800 ring-zinc-500/20'
  }[status] || 'bg-zinc-100 text-zinc-700 ring-zinc-500/20'
}

function formatDate(value) {
  if (!value) return 'Never'
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(new Date(value))
}

function compact(value, size = 12) {
  if (!value) return ''
  if (value.length <= size * 2 + 1) return value
  return `${value.slice(0, size)}...${value.slice(-size)}`
}

function identifierText(order) {
  return (order.identifiers || []).map(identifier => `${identifier.type}:${identifier.value}`).join(', ')
}

function fingerprint(value) {
  if (!value) return ''
  return value.match(/.{1,2}/g)?.join(':') || value
}
</script>

<template>
  <main class="min-h-screen bg-[#f7f7f4] text-zinc-950">
    <div v-if="loading" class="flex min-h-screen items-center justify-center">
      <RefreshCw class="h-6 w-6 animate-spin text-teal-700" />
    </div>

    <section v-else-if="!loggedIn" class="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6">
      <div class="border-y border-zinc-300 py-8">
        <div class="mb-6 flex h-11 w-11 items-center justify-center rounded bg-zinc-950 text-white">
          <ShieldCheck class="h-6 w-6" />
        </div>
        <h1 class="text-3xl font-semibold tracking-normal">Quick-PKI Admin</h1>
        <p class="mt-3 text-sm leading-6 text-zinc-600">
          Sign in with the configured OpenID provider to inspect ACME accounts, requests, and CA state.
        </p>
        <button class="focus-ring mt-8 inline-flex items-center gap-2 rounded bg-teal-700 px-4 py-2 text-sm font-medium text-white hover:bg-teal-800" @click="login">
          <ShieldCheck class="h-4 w-4" />
          Sign in
        </button>
        <p v-if="error" class="mt-4 text-sm text-rose-700">{{ error }}</p>
      </div>
    </section>

    <div v-else>
      <header class="border-b border-zinc-300 bg-white">
        <div class="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-4 sm:px-6 lg:flex-row lg:items-center lg:justify-between lg:px-8">
          <div class="flex items-center gap-3">
            <div class="flex h-10 w-10 items-center justify-center rounded bg-zinc-950 text-white">
              <ShieldCheck class="h-5 w-5" />
            </div>
            <div>
              <h1 class="text-xl font-semibold tracking-normal">Quick-PKI Admin</h1>
              <p class="text-sm text-zinc-500">ACME registration and issuance management</p>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <button class="focus-ring inline-flex h-9 items-center gap-2 rounded border border-zinc-300 bg-white px-3 text-sm font-medium text-zinc-700 hover:bg-zinc-100" title="Refresh" @click="refreshAll">
              <RefreshCw class="h-4 w-4" />
              Refresh
            </button>
            <button class="focus-ring inline-flex h-9 items-center gap-2 rounded border border-zinc-300 bg-white px-3 text-sm font-medium text-zinc-700 hover:bg-zinc-100" title="Sign out" @click="logout">
              <LogOut class="h-4 w-4" />
              Sign out
            </button>
          </div>
        </div>
      </header>

      <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <p v-if="error" class="mb-4 border-l-4 border-rose-600 bg-rose-50 px-4 py-3 text-sm text-rose-800">{{ error }}</p>

        <div class="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <nav class="flex flex-wrap gap-2">
            <button
              v-for="tab in tabs"
              :key="tab.id"
              class="focus-ring inline-flex h-10 items-center gap-2 rounded px-3 text-sm font-medium"
              :class="activeTab === tab.id ? 'bg-zinc-950 text-white' : 'border border-zinc-300 bg-white text-zinc-700 hover:bg-zinc-100'"
              @click="activeTab = tab.id; selectedOrder = null"
            >
              <component :is="tab.icon" class="h-4 w-4" />
              {{ tab.label }}
            </button>
          </nav>

          <label v-if="activeTab === 'accounts' || activeTab === 'orders'" class="relative block w-full lg:w-80">
            <Search class="absolute left-3 top-2.5 h-4 w-4 text-zinc-400" />
            <input v-model="query" class="focus-ring h-10 w-full rounded border border-zinc-300 bg-white pl-9 pr-3 text-sm" placeholder="Search" />
          </label>
        </div>

        <section v-if="activeTab === 'overview'" class="space-y-6">
          <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <div v-for="(value, label) in summary.totals" :key="label" class="rounded border border-zinc-300 bg-white p-4">
              <p class="text-xs font-medium uppercase text-zinc-500">{{ label }}</p>
              <p class="mt-2 text-3xl font-semibold">{{ value }}</p>
            </div>
          </div>

          <div class="grid gap-6 lg:grid-cols-2">
            <div class="rounded border border-zinc-300 bg-white">
              <div class="border-b border-zinc-200 px-4 py-3">
                <h2 class="font-semibold">Order Statuses</h2>
              </div>
              <div class="divide-y divide-zinc-200">
                <div v-for="(count, status) in summary.orderStatuses" :key="status" class="flex items-center justify-between px-4 py-3">
                  <span class="rounded px-2 py-1 text-xs font-medium ring-1" :class="statusClass(status)">{{ status }}</span>
                  <span class="font-semibold">{{ count }}</span>
                </div>
              </div>
            </div>

            <div class="rounded border border-zinc-300 bg-white">
              <div class="border-b border-zinc-200 px-4 py-3">
                <h2 class="font-semibold">Recent Requests</h2>
              </div>
              <button v-for="order in recentOrders" :key="order.id" class="focus-ring flex w-full items-center justify-between border-b border-zinc-200 px-4 py-3 text-left last:border-b-0 hover:bg-zinc-50" @click="activeTab = 'orders'; openOrder(order)">
                <span>
                  <span class="block text-sm font-medium">{{ identifierText(order) || compact(order.id) }}</span>
                  <span class="block text-xs text-zinc-500">{{ formatDate(order.createdAt) }}</span>
                </span>
                <span class="rounded px-2 py-1 text-xs font-medium ring-1" :class="statusClass(order.status)">{{ order.status }}</span>
              </button>
            </div>
          </div>
        </section>

        <section v-if="activeTab === 'accounts'" class="overflow-hidden rounded border border-zinc-300 bg-white">
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-zinc-200 text-sm">
              <thead class="bg-zinc-100 text-left text-xs font-semibold uppercase text-zinc-500">
                <tr>
                  <th class="px-4 py-3">Account</th>
                  <th class="px-4 py-3">Contact</th>
                  <th class="px-4 py-3">Status</th>
                  <th class="px-4 py-3">Orders</th>
                  <th class="px-4 py-3">Created</th>
                  <th class="px-4 py-3">Last request</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-zinc-200">
                <tr v-for="account in filteredAccounts" :key="account.id">
                  <td class="px-4 py-3">
                    <span class="block font-medium">{{ compact(account.id) }}</span>
                    <span class="block text-xs text-zinc-500">{{ compact(account.keyThumbprint, 18) }}</span>
                  </td>
                  <td class="px-4 py-3 text-zinc-600">{{ account.contact?.join(', ') || 'None' }}</td>
                  <td class="px-4 py-3"><span class="rounded px-2 py-1 text-xs font-medium ring-1" :class="statusClass(account.status)">{{ account.status }}</span></td>
                  <td class="px-4 py-3 font-medium">{{ account.orderCount }}</td>
                  <td class="px-4 py-3 text-zinc-600">{{ formatDate(account.createdAt) }}</td>
                  <td class="px-4 py-3 text-zinc-600">{{ formatDate(account.lastOrderAt) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section v-if="activeTab === 'orders'" class="grid gap-5 lg:grid-cols-[minmax(0,1fr)_420px]">
          <div class="overflow-hidden rounded border border-zinc-300 bg-white">
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-zinc-200 text-sm">
                <thead class="bg-zinc-100 text-left text-xs font-semibold uppercase text-zinc-500">
                  <tr>
                    <th class="px-4 py-3">Request</th>
                    <th class="px-4 py-3">Status</th>
                    <th class="px-4 py-3">Checks</th>
                    <th class="px-4 py-3">Certificate</th>
                    <th class="px-4 py-3">Created</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-zinc-200">
                  <tr v-for="order in filteredOrders" :key="order.id" class="cursor-pointer hover:bg-zinc-50" @click="openOrder(order)">
                    <td class="px-4 py-3">
                      <span class="block font-medium">{{ identifierText(order) || compact(order.id) }}</span>
                      <span class="block text-xs text-zinc-500">{{ compact(order.accountThumbprint, 18) }}</span>
                    </td>
                    <td class="px-4 py-3"><span class="rounded px-2 py-1 text-xs font-medium ring-1" :class="statusClass(order.status)">{{ order.status }}</span></td>
                    <td class="px-4 py-3 text-zinc-600">{{ order.authorizationCount }} authz / {{ order.challengeCount }} challenges</td>
                    <td class="px-4 py-3">
                      <BadgeCheck v-if="order.certificateIssued" class="h-5 w-5 text-teal-700" />
                      <span v-else class="text-zinc-400">Pending</span>
                    </td>
                    <td class="px-4 py-3 text-zinc-600">{{ formatDate(order.createdAt) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <aside class="rounded border border-zinc-300 bg-white">
            <div class="border-b border-zinc-200 px-4 py-3">
              <h2 class="font-semibold">Request Detail</h2>
            </div>
            <div v-if="!selectedOrder" class="px-4 py-8 text-sm text-zinc-500">Select a request.</div>
            <div v-else class="space-y-4 p-4 text-sm">
              <div>
                <p class="text-xs font-medium uppercase text-zinc-500">Order</p>
                <p class="break-all font-medium">{{ selectedOrder.order.id }}</p>
              </div>
              <div class="flex flex-wrap gap-2">
                <span class="rounded px-2 py-1 text-xs font-medium ring-1" :class="statusClass(selectedOrder.order.status)">{{ selectedOrder.order.status }}</span>
                <span v-if="selectedOrder.order.certificateIssued" class="rounded bg-teal-100 px-2 py-1 text-xs font-medium text-teal-800 ring-1 ring-teal-600/20">certificate issued</span>
              </div>
              <div v-for="authz in selectedOrder.authorizations" :key="authz.id" class="rounded border border-zinc-200 p-3">
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <p class="font-medium">{{ authz.identifierType }}:{{ authz.identifierValue }}</p>
                    <p class="text-xs text-zinc-500">Expires {{ formatDate(authz.expiresAt) }}</p>
                  </div>
                  <span class="rounded px-2 py-1 text-xs font-medium ring-1" :class="statusClass(authz.status)">{{ authz.status }}</span>
                </div>
                <div class="mt-3 space-y-2">
                  <div v-for="challenge in authz.challenges" :key="challenge.id" class="flex items-center justify-between gap-3 text-xs">
                    <span class="font-medium">{{ challenge.type }}</span>
                    <span class="rounded px-2 py-1 font-medium ring-1" :class="statusClass(challenge.status)">{{ challenge.status }}</span>
                  </div>
                </div>
              </div>
            </div>
          </aside>
        </section>

        <section v-if="activeTab === 'ca'" class="grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
          <div class="rounded border border-zinc-300 bg-white">
            <div class="flex items-center justify-between border-b border-zinc-200 px-4 py-3">
              <h2 class="font-semibold">Active Certificate Authority</h2>
              <button class="focus-ring inline-flex h-9 items-center gap-2 rounded bg-rose-700 px-3 text-sm font-medium text-white hover:bg-rose-800 disabled:cursor-not-allowed disabled:bg-rose-300" :disabled="rotating" @click="rotateCA">
                <RotateCw class="h-4 w-4" :class="{ 'animate-spin': rotating }" />
                Rotate
              </button>
            </div>
            <div v-if="!ca" class="p-4 text-sm text-zinc-500">No CA material has been created yet.</div>
            <div v-else class="grid gap-4 p-4 text-sm sm:grid-cols-2">
              <div>
                <p class="text-xs font-medium uppercase text-zinc-500">Subject</p>
                <p class="mt-1 break-words font-medium">{{ ca.subject }}</p>
              </div>
              <div>
                <p class="text-xs font-medium uppercase text-zinc-500">Serial</p>
                <p class="mt-1 break-all font-medium">{{ ca.serial }}</p>
              </div>
              <div>
                <p class="text-xs font-medium uppercase text-zinc-500">Created</p>
                <p class="mt-1">{{ formatDate(ca.createdAt) }}</p>
              </div>
              <div>
                <p class="text-xs font-medium uppercase text-zinc-500">Valid until</p>
                <p class="mt-1">{{ formatDate(ca.notAfter) }}</p>
              </div>
              <div class="sm:col-span-2">
                <p class="text-xs font-medium uppercase text-zinc-500">SHA-256 fingerprint</p>
                <p class="mt-1 break-all font-mono text-xs">{{ fingerprint(ca.fingerprint) }}</p>
              </div>
            </div>
          </div>

          <aside class="rounded border border-zinc-300 bg-white p-4">
            <h2 class="font-semibold">Root PEM</h2>
            <pre class="mt-3 max-h-[32rem] overflow-auto rounded bg-zinc-950 p-3 text-xs text-zinc-100">{{ ca?.pem || '' }}</pre>
          </aside>
        </section>
      </div>
    </div>
  </main>
</template>
