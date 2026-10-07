module.exports = {
  apps: [
    {
      name: "vtuber-nexus",
      script: "server.js",
      cwd: __dirname + "/..",
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      max_memory_restart: "700M",
      kill_timeout: 10000,
      listen_timeout: 15000,
      env_production: {
        NODE_ENV: "production"
      },
      error_file: "./logs/error.log",
      out_file: "./logs/output.log",
      merge_logs: true,
      time: true
    }
  ]
};
