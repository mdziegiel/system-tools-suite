<template>
  <section class="grid-section">
    <h2>{{ title }}</h2>
    <p v-if="!items.length" class="empty">{{ empty || 'No tools match.' }}</p>
    <div class="grid">
      <article v-for="t in items" :key="t.slug" class="card" @click="$emit('open', t.slug)">
        <div class="card-head">
          <span class="badge">{{ t.category.replace(' Tools','') }}</span>
          <button @click.stop="$emit('favorite', t.slug)" class="heart">{{ favorites.includes(t.slug) ? '♥' : '♡' }}</button>
        </div>
        <h3>{{ t.name }}</h3>
        <p>{{ t.description }}</p>
        <small v-if="t.badge === 'new'">Newest</small>
      </article>
    </div>
  </section>
</template>
<script setup>
defineProps({ title:String, items:Array, empty:String, favorites:{type:Array,default:()=>[]} })
defineEmits(['open','favorite'])
</script>
