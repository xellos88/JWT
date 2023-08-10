<!-- <template>
<div>
  아이디:<input type="text">비밀번호:<input type="text">
  <button @click="login()">로그인</button>
</div>
</template>
    
<script>
import axios from "axios";

export default {
  name: 'App',
  data(){
    return {
      token:'',
    }
  },
  methods:{
    login(){
      axios.get('http://localhost:8000/api/token?id=ppp')
      .then(res=>{
        console.log(res.data);
        this.token=res.data.token;
      })
    },
  },
}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style> -->
<template>
  <div>
    <router-view></router-view>
  </div>
</template>

<script>
// import axios from "axios";
import router from './router'

export default {
  name: 'App',
  methods: {
    login() {
      router.push('main');
      // axios.get('http://localhost:8000/api/token?id=ppp')
      // .then(res => {
      //   console.log(res.data);
      //     this.$store.state.token = res.data.token; 
      // })
      // .catch(err => {
      //   if( err.status >= 400){
      //     console.log(err);
      //   }
      // });
    },
    logout(){
      router.push('login');
    }
  },
}
</script>