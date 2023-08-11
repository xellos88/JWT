<template>
    <div>
        <h1>Home 페이지</h1>
        <button @click="btn('login')">로그인 페이지</button><br>
        <button @click="btn('main')">메인 페이지</button>
    </div>
</template>
<script>
import router from '../router.js';

export default {
    name: "HomeComponent",
    methods: {
        btn(path){
            router.push(path);
        }
    }
};
</script>
