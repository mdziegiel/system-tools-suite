<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand"><div class="logo">STS</div><div><strong>System Tools</strong><span>Sysadmin Operations Suite</span></div></div>
      <button class="home" @click="active=null">Home</button>
      <section v-for="cat in categories" :key="cat.name" class="nav-section">
        <button class="cat" @click="toggle(cat.name)"><span>{{ cat.name }}</span><span>{{ open[cat.name] ? '−' : '+' }}</span></button>
        <div v-show="open[cat.name]" class="cat-tools">
          <button v-for="t in cat.tools" :key="t[0]" :class="['nav-tool',{selected:active===t[0]}]" @click="active=t[0]">{{ t[1] }}</button>
        </div>
      </section>
    </aside>
    <main class="main">
      <header class="top"><div><h1>{{ activeTool?.name || 'System Tools Suite' }}</h1><p>{{ activeTool?.description || 'Original sysadmin, network, security, DevOps, UniFi, and forensic utilities.' }}</p></div><input v-model="query" class="search" placeholder="Search tools, categories, capabilities..." /></header>
      <ToolPage v-if="active" :key="active" :tool="activeTool" :favorites="favorites" @favorite="fav" @back="active=null" />
      <template v-else>
        <section class="hero"><h2>Professional infrastructure tools. No toy scaffolding.</h2><p>Run server-side diagnostics from the container, do sensitive browser-only operations locally, and keep forensic cases in persistent SQLite storage.</p></section>
        <ToolGrid title="Newest Tools" :items="newest" :favorites="favorites" @favorite="fav" @open="active=$event" />
        <ToolGrid title="Favorites" :items="favoriteTools" :favorites="favorites" empty="Pinned tools appear here. Click the heart on any card." @favorite="fav" @open="active=$event" />
        <ToolGrid title="All Tools" :items="filtered" :favorites="favorites" @favorite="fav" @open="active=$event" />
      </template>
    </main>
  </div>
</template>
<script setup>
import { computed, reactive, ref } from 'vue'
import ToolGrid from './components/ToolGrid.vue'
import ToolPage from './components/ToolPage.vue'
import { categories, tools } from './tools.js'
const active = ref(null), query = ref('')
const open = reactive(Object.fromEntries(categories.map(c=>[c.name,true])))
const favorites = ref(JSON.parse(localStorage.getItem('sts:favorites') || '[]'))
function toggle(name){ open[name]=!open[name] }
function fav(slug){ favorites.value = favorites.value.includes(slug) ? favorites.value.filter(x=>x!==slug) : [...favorites.value, slug]; localStorage.setItem('sts:favorites', JSON.stringify(favorites.value)) }
const activeTool = computed(()=>tools.find(t=>t.slug===active.value))
const newest = computed(()=>tools.filter(t=>t.badge==='new'))
const favoriteTools = computed(()=>tools.filter(t=>favorites.value.includes(t.slug)))
const filtered = computed(()=>tools.filter(t=>(t.name+t.description+t.category).toLowerCase().includes(query.value.toLowerCase())))
</script>
