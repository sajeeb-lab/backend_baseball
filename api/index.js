<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Coach Dashboard – Ambassadors Baseball</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=Open+Sans:wght@300;400;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--navy:#0a1628;--red:#c8102e;--red2:#a50d25;--white:#ffffff;--light:#f4f6f9;--mid:#dce3ec;--text:#1a1a2e;--sub:#5a6a7a}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Open Sans',sans-serif;background:var(--light);color:var(--text);min-height:100vh}
.page-header{background:linear-gradient(135deg,#1a3fc4 0%,#1535a8 100%);padding:2rem 2rem 1.6rem;position:relative;overflow:hidden}
.page-header::before{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/svg%3E")}
.page-header-inner{max-width:1100px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:1rem;position:relative}
.header-left h1{font-family:'Oswald',sans-serif;font-size:clamp(1.2rem,3vw,1.8rem);font-weight:700;color:var(--white);letter-spacing:.04em;text-transform:uppercase}
.header-left p{color:rgba(255,255,255,.7);font-size:.8rem;margin-top:.25rem}
.logout-btn{display:inline-flex;align-items:center;gap:.5rem;background:rgba(255,255,255,.15);color:var(--white);border:none;font-family:'Oswald',sans-serif;font-size:.75rem;font-weight:500;letter-spacing:.1em;text-transform:uppercase;padding:9px 16px;border-radius:4px;cursor:pointer;transition:background .2s}
.logout-btn:hover{background:rgba(200,16,46,.5)}
.logout-btn svg{width:15px;height:15px}
.main{max-width:1100px;margin:0 auto;padding:2rem 1.5rem 4rem}
.card{background:var(--white);border-radius:6px;box-shadow:0 2px 12px rgba(0,0,0,.07);overflow:hidden;margin-bottom:1.4rem}
.card-header{background:var(--red);padding:11px 20px;font-family:'Oswald',sans-serif;font-size:.9rem;font-weight:600;color:var(--white);letter-spacing:.12em;text-transform:uppercase;text-align:center}
.card-body{padding:1.4rem 1.6rem 1.6rem}
.welcome-banner{background:linear-gradient(135deg,var(--navy) 0%,#162845 100%);border-radius:6px;padding:1.4rem 1.6rem;margin-bottom:1.4rem;display:flex;align-items:center;gap:1rem;position:relative;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1)}
.welcome-banner::after{content:'';position:absolute;right:-40px;bottom:-40px;width:140px;height:140px;border-radius:50%;background:rgba(200,16,46,.15);pointer-events:none}
.welcome-icon{width:52px;height:52px;border-radius:50%;background:var(--red);display:flex;align-items:center;justify-content:center;flex-shrink:0;position:relative;z-index:1}
.welcome-icon svg{width:26px;height:26px;color:var(--white)}
.welcome-text{position:relative;z-index:1}
.welcome-text h2{font-family:'Oswald',sans-serif;font-size:1.2rem;font-weight:700;color:var(--white);text-transform:uppercase;letter-spacing:.04em}
.welcome-text p{color:rgba(255,255,255,.7);font-size:.82rem;margin-top:.25rem}
.section-tabs{display:flex;gap:.5rem;margin-bottom:1.4rem;flex-wrap:wrap}
.section-tab{display:inline-flex;align-items:center;gap:.35rem;background:var(--white);border:1.5px solid var(--mid);border-radius:6px;padding:6px 10px;font-family:'Oswald',sans-serif;font-size:.7rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--sub);cursor:pointer;transition:all .15s;white-space:nowrap}
.section-tab:hover{border-color:var(--navy);color:var(--navy)}
.section-tab.active{background:var(--navy);border-color:var(--navy);color:var(--white)}
.section-tab svg{width:13px;height:13px;flex-shrink:0}
.dash-panel{display:none}
.dash-panel.active{display:block}
.field-group{display:flex;flex-direction:column;gap:.42rem;margin-bottom:1.1rem}
.field-label{font-size:.68rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--sub)}
.field-input,.field-select,.field-textarea{border:1.5px solid var(--mid);border-radius:8px;padding:11px 14px;font-size:.88rem;font-family:'Open Sans',sans-serif;color:var(--text);background:var(--white);outline:none;transition:border-color .15s,box-shadow .15s;width:100%}
.field-input::placeholder,.field-textarea::placeholder{color:#b0bec5}
.field-input:focus,.field-select:focus,.field-textarea:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(200,16,46,.08)}
.field-textarea{resize:vertical;min-height:100px;line-height:1.6}
/* Hide number input spinner buttons */
input[type="number"]::-webkit-outer-spin-button,
input[type="number"]::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
input[type="number"] {
  -moz-appearance: textfield;
}
.form-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:0 1.4rem}
.form-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0 1.4rem}
.save-btn{display:inline-flex;align-items:center;gap:.5rem;background:var(--navy);color:var(--white);border:none;border-radius:8px;padding:11px 22px;font-family:'Oswald',sans-serif;font-size:.82rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:background .15s;margin-top:.4rem;white-space:nowrap}
.save-btn:hover{background:#162845}
.save-btn:disabled{opacity:.6;cursor:not-allowed}
.msg{padding:.75rem 1rem;border-radius:6px;font-size:.82rem;margin-bottom:1.1rem;display:none}
.msg.error{background:#fef3f5;border:1px solid #f5c6cb;color:var(--red);display:block}
.msg.success{background:#f0fdf4;border:1px solid #bbf7d0;color:#16a34a;display:block}
.info-note{background:#fffbea;border:1px solid #fde68a;border-radius:6px;padding:.75rem 1rem;font-size:.8rem;color:#92400e;margin-bottom:1.2rem;display:flex;align-items:flex-start;gap:.6rem}
.info-note svg{width:15px;height:15px;flex-shrink:0;margin-top:2px}
.section-divider{border:none;border-top:1px solid var(--mid);margin:1.3rem 0}
.asst-label{font-family:'Oswald',sans-serif;font-size:.78rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--white);background:var(--navy);padding:7px 14px;border-radius:4px;display:inline-block;margin-bottom:1.1rem}

/* TRYOUTS */
.tryouts-list{display:flex;flex-direction:column;gap:.75rem}
.tryout-item{background:var(--light);border:1.5px solid var(--mid);border-radius:8px;padding:1rem 1.2rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.tryout-item-date{font-family:'Oswald',sans-serif;font-size:1rem;font-weight:700;color:var(--navy)}
.tryout-item-meta{font-size:.78rem;color:var(--sub);margin-top:3px}
.tryout-item-fee{display:inline-block;background:var(--navy);color:var(--white);font-family:'Oswald',sans-serif;font-size:.62rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:3px 10px;border-radius:20px;margin-left:.5rem;vertical-align:middle}
.delete-btn{display:inline-flex;align-items:center;gap:.35rem;background:none;border:1.5px solid #f5c6cb;border-radius:6px;padding:6px 12px;font-family:'Oswald',sans-serif;font-size:.68rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--red);cursor:pointer;transition:all .15s;flex-shrink:0}
.delete-btn:hover{background:var(--red);color:var(--white);border-color:var(--red)}
.delete-btn svg{width:13px;height:13px}
.no-tryouts-dash{text-align:center;padding:2rem;color:var(--sub);font-size:.86rem;background:var(--light);border-radius:6px;border:1.5px dashed var(--mid)}


/* LOADING */
.loading-state{text-align:center;padding:3rem 2rem;color:var(--sub)}
.spinner{width:32px;height:32px;border:3px solid var(--mid);border-top-color:var(--red);border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 1rem}
@keyframes spin{to{transform:rotate(360deg)}}
.btn-spinner{width:15px;height:15px;border:2.5px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;display:inline-block;vertical-align:middle}

/* PHOTO UPLOAD */
.photo-upload-wrap{display:flex;align-items:center;gap:1.4rem;margin-bottom:1.3rem;padding:1.1rem 1.2rem;background:var(--light);border-radius:8px;border:1.5px solid var(--mid)}
.photo-preview{width:72px;height:72px;border-radius:50%;background:#dce3ec;border:2px solid var(--mid);flex-shrink:0;overflow:hidden;display:flex;align-items:center;justify-content:center}
.photo-preview img{width:100%;height:100%;object-fit:cover;border-radius:50%}
.photo-preview svg{width:32px;height:32px;color:#aab}
.photo-btn-row{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.4rem}
.photo-edit-btn{display:inline-flex;align-items:center;gap:.4rem;padding:8px 14px;border-radius:6px;font-family:'Oswald',sans-serif;font-size:.74rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;cursor:pointer;border:none;transition:background .15s;white-space:nowrap}
.photo-edit-btn.edit{background:var(--navy);color:#fff}.photo-edit-btn.edit:hover{background:#162845}
.photo-edit-btn.delete{background:#fef3f5;color:var(--red);border:1.5px solid #f5c6cb}.photo-edit-btn.delete:hover{background:#fde8ec}
.photo-upload-right{flex:1;min-width:0}
.photo-upload-right .field-label{margin-bottom:.5rem;display:block}
.photo-upload-btn{display:inline-flex;align-items:center;gap:.5rem;background:var(--white);border:1.5px solid var(--mid);border-radius:6px;padding:8px 14px;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--navy);cursor:pointer;transition:all .15s}
.photo-upload-btn:hover{border-color:var(--red);color:var(--red)}
.photo-upload-btn svg{width:14px;height:14px}
.photo-upload-hint{font-size:.72rem;color:var(--sub);margin-top:.4rem}
/* REGISTER TOGGLE */
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:.9rem 1rem;background:var(--light);border-radius:8px;border:1.5px solid var(--mid);margin-bottom:1.1rem;gap:1rem}
.toggle-label-wrap{display:flex;flex-direction:column;gap:.22rem}
.toggle-label-main{font-size:.75rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text)}
.toggle-label-sub{font-size:.72rem;color:var(--sub)}
.toggle-switch{position:relative;display:inline-block;width:46px;height:26px;flex-shrink:0}
.toggle-switch input{opacity:0;width:0;height:0;position:absolute}
.toggle-slider{position:absolute;cursor:pointer;inset:0;background:#ccc;border-radius:26px;transition:.3s}
.toggle-slider::before{content:'';position:absolute;width:20px;height:20px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.3s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.toggle-switch input:checked+.toggle-slider{background:var(--navy)}
.toggle-switch input:checked+.toggle-slider::before{transform:translateX(20px)}
.toggle-status{font-family:'Oswald',sans-serif;font-size:.68rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:3px 10px;border-radius:20px;margin-left:.6rem;vertical-align:middle;flex-shrink:0}
.toggle-status.on{background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0}
.toggle-status.off{background:#fef3f5;color:var(--red);border:1px solid #f5c6cb}
.photo-uploading{font-size:.75rem;color:var(--sub);margin-top:.4rem;display:none}
input[type="file"].hidden-file{display:none}
.asst-photo-wrap{display:flex;align-items:center;gap:1rem;margin-bottom:1.1rem;padding:.9rem 1rem;background:var(--light);border-radius:8px;border:1.5px solid var(--mid)}
.asst-photo-preview{width:52px;height:52px;border-radius:50%;background:#dce3ec;border:2px solid var(--mid);flex-shrink:0;overflow:hidden;display:flex;align-items:center;justify-content:center}
.asst-photo-preview img{width:100%;height:100%;object-fit:cover;border-radius:50%}
.asst-photo-preview svg{width:24px;height:24px;color:#aab}

/* ROSTER */
.roster-mgmt-table{width:100%;border-collapse:collapse;font-size:.84rem}
.roster-mgmt-table thead tr{background:var(--navy)}
.roster-mgmt-table thead th{padding:10px 14px;text-align:left;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;color:var(--white);letter-spacing:.1em;text-transform:uppercase;white-space:nowrap}
.roster-mgmt-table tbody tr{border-bottom:1px solid var(--mid);transition:background .12s}
.roster-mgmt-table tbody tr:last-child{border-bottom:none}
.roster-mgmt-table tbody tr:hover{background:var(--light)}
.roster-mgmt-table td{padding:10px 14px;vertical-align:middle;font-size:.83rem}
.roster-mgmt-table td:first-child{font-weight:600;color:var(--navy)}
.roster-edit-btn{display:inline-flex;align-items:center;gap:4px;background:none;border:1.5px solid var(--mid);border-radius:5px;padding:5px 10px;font-family:'Oswald',sans-serif;font-size:.65rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--navy);cursor:pointer;transition:all .15s;margin-right:4px}
.roster-edit-btn:hover{background:var(--navy);color:var(--white);border-color:var(--navy)}
.roster-del-btn{display:inline-flex;align-items:center;gap:4px;background:none;border:1.5px solid #f5c6cb;border-radius:5px;padding:5px 10px;font-family:'Oswald',sans-serif;font-size:.65rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--red);cursor:pointer;transition:all .15s}
.roster-del-btn:hover{background:var(--red);color:var(--white);border-color:var(--red)}
.roster-del-btn svg,.roster-edit-btn svg{width:12px;height:12px}
.empty-roster-dash{text-align:center;padding:2.5rem;color:var(--sub);font-size:.88rem;background:var(--light);border-radius:0 0 6px 6px}
.roster-table-wrap{overflow-x:auto}

/* EDIT MODAL */
.edit-overlay{position:fixed;inset:0;background:rgba(10,22,40,.55);backdrop-filter:blur(4px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:1rem;opacity:0;pointer-events:none;transition:opacity .25s}
.edit-overlay.open{opacity:1;pointer-events:all}
.edit-modal{background:var(--white);border-radius:8px;box-shadow:0 20px 60px rgba(0,0,0,.25);width:100%;max-width:560px;overflow:hidden;transform:translateY(20px) scale(.97);transition:transform .28s cubic-bezier(.4,0,.2,1)}
.edit-overlay.open .edit-modal{transform:translateY(0) scale(1)}
.edit-modal-head{background:var(--red);padding:1rem 1.4rem;display:flex;align-items:center;justify-content:space-between}
.edit-modal-head h3{font-family:'Oswald',sans-serif;font-size:1rem;font-weight:700;color:var(--white);text-transform:uppercase;letter-spacing:.08em}
.edit-modal-close{background:rgba(255,255,255,.2);border:none;color:var(--white);width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s}
.edit-modal-close:hover{background:rgba(255,255,255,.35)}
.edit-modal-close svg{width:13px;height:13px}
.edit-modal-body{padding:1.4rem 1.5rem 1.6rem}
.edit-modal-grid{display:grid;grid-template-columns:1fr 1fr;gap:.9rem 1.2rem}
.edit-modal-foot{padding:.9rem 1.4rem;border-top:1px solid var(--mid);display:flex;justify-content:flex-end;gap:.6rem}
.edit-cancel-btn{background:none;border:1.5px solid var(--mid);border-radius:6px;padding:9px 20px;font-family:'Oswald',sans-serif;font-size:.8rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--sub);cursor:pointer;transition:all .15s}
.edit-cancel-btn:hover{border-color:var(--navy);color:var(--navy)}
.edit-save-btn{background:var(--navy);border:none;border-radius:6px;padding:9px 24px;font-family:'Oswald',sans-serif;font-size:.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--white);cursor:pointer;transition:background .15s}
.edit-save-btn:hover{background:#162845}



/* SCHEDULE */
.sched-mgmt-table{width:100%;border-collapse:collapse;font-size:.84rem}
.sched-mgmt-table thead tr{background:var(--navy)}
.sched-mgmt-table thead th{padding:10px 14px;text-align:left;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;color:var(--white);letter-spacing:.1em;text-transform:uppercase;white-space:nowrap}
.sched-mgmt-table tbody tr{border-bottom:1px solid var(--mid);transition:background .12s}
.sched-mgmt-table tbody tr:last-child{border-bottom:none}
.sched-mgmt-table tbody tr:hover{background:var(--light)}
.sched-mgmt-table td{padding:10px 14px;vertical-align:middle;font-size:.83rem}
.sched-mgmt-table td:first-child{font-weight:600;color:var(--navy);white-space:nowrap}
.sched-table-wrap{overflow-x:auto}
.no-schedule-dash{text-align:center;padding:2.5rem;color:var(--sub);font-size:.88rem;background:var(--light);border-radius:0 0 6px 6px}
.tryreg-tryout-card{background:var(--white);border:2px solid var(--mid);border-radius:10px;padding:1.2rem 1.3rem 1rem;cursor:pointer;transition:box-shadow .15s,transform .15s,border-color .15s;display:flex;flex-direction:column;gap:.45rem}
.tryreg-tryout-card:hover{box-shadow:0 6px 24px rgba(0,0,0,.1);transform:translateY(-2px);border-color:var(--red)}
.tryreg-tryout-card.selected{border-color:var(--red);box-shadow:0 6px 24px rgba(200,16,46,.15)}
.tryreg-tryout-card-top{display:flex;align-items:center;justify-content:space-between;gap:.5rem}
.tryreg-count-badge{font-family:'Oswald',sans-serif;font-size:.65rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;background:#fef3f5;color:var(--red);border:1px solid #f5c6cb;padding:3px 9px;border-radius:20px;white-space:nowrap}
.tryreg-tryout-date{font-family:'Oswald',sans-serif;font-size:1.15rem;font-weight:700;color:var(--navy);line-height:1.1}
.tryreg-tryout-meta{font-size:.78rem;color:var(--sub)}
.tryreg-view-regs-btn{margin-top:.5rem;text-align:center;background:var(--navy);color:var(--white);font-family:'Oswald',sans-serif;font-size:.75rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;padding:8px 0;border-radius:6px;transition:background .15s}
.tryreg-tryout-card:hover .tryreg-view-regs-btn,.tryreg-tryout-card.selected .tryreg-view-regs-btn{background:var(--red)}
.tryreg-table{width:100%;border-collapse:collapse;font-size:.83rem}
.tryreg-table thead tr{background:var(--navy)}
.tryreg-table thead th{padding:10px 14px;text-align:left;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;color:var(--white);letter-spacing:.1em;text-transform:uppercase;white-space:nowrap}
.tryreg-table tbody tr{border-bottom:1px solid var(--mid);transition:background .12s}
.tryreg-table tbody tr:last-child{border-bottom:none}
.tryreg-table tbody tr:hover{background:var(--light)}
.tryreg-table td{padding:10px 14px;vertical-align:middle;font-size:.82rem;color:var(--text)}
.tryreg-table td:first-child{font-weight:600;color:var(--navy)}

/* COST CALCULATOR */
.calc-section{margin-bottom:1.6rem}
.calc-section-title{font-family:'Oswald',sans-serif;font-size:.78rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--white);background:var(--navy);padding:8px 14px;border-radius:4px;display:block;margin-bottom:1rem}
.calc-grid{display:grid;grid-template-columns:1fr 1fr;gap:.85rem 1.4rem}
.calc-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:.85rem 1.4rem}
.calc-field{display:flex;flex-direction:column;gap:.38rem}
.calc-label{font-size:.65rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub)}
.calc-input{border:1.5px solid var(--mid);border-radius:8px;padding:10px 14px;font-size:.88rem;font-family:'Open Sans',sans-serif;color:var(--text);background:var(--white);outline:none;transition:border-color .15s,box-shadow .15s;width:100%}
.calc-input:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(200,16,46,.08)}
.calc-input[readonly]{background:var(--light);color:var(--navy);font-weight:700;cursor:default}
/* Hide number input spinner buttons */
.calc-input::-webkit-outer-spin-button,.calc-input::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
.calc-input[type="number"]{-moz-appearance:textfield}
.calc-prefix{position:relative}
.calc-prefix::before{content:'$';position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--sub);font-size:.88rem;pointer-events:none}
.calc-prefix .calc-input{padding-left:24px}
.calc-divider{border:none;border-top:1px solid var(--mid);margin:1.4rem 0}
.calc-totals-card{background:linear-gradient(135deg,var(--navy) 0%,#162845 100%);border-radius:8px;padding:1.4rem 1.6rem;margin-top:1.4rem}
.calc-totals-title{font-family:'Oswald',sans-serif;font-size:.9rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--white);margin-bottom:1.1rem}
.calc-total-row{display:flex;align-items:center;justify-content:space-between;padding:.6rem 0;border-bottom:1px solid rgba(255,255,255,.08)}
.calc-total-row:last-child{border-bottom:none}
.calc-total-label{font-size:.8rem;color:rgba(255,255,255,.65)}
.calc-total-value{font-family:'Oswald',sans-serif;font-size:1rem;font-weight:700;color:var(--white)}
.calc-total-row.highlight .calc-total-label{color:var(--white);font-weight:600;font-size:.85rem}
.calc-total-row.highlight .calc-total-value{color:#ffd700;font-size:1.2rem}
.calc-total-row.grand .calc-total-label{color:var(--white);font-weight:700;font-size:.9rem}
.calc-total-row.grand .calc-total-value{color:#ff6b6b;font-size:1.3rem}
.calc-other-wrap{display:flex;flex-direction:column;gap:.6rem;margin-top:.5rem}
.calc-other-row{display:grid;grid-template-columns:1fr 1fr auto;gap:.6rem;align-items:end}
.calc-add-other-btn{display:inline-flex;align-items:center;gap:.4rem;background:none;border:1.5px dashed var(--mid);border-radius:6px;padding:8px 14px;font-family:'Oswald',sans-serif;font-size:.74rem;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--sub);cursor:pointer;transition:all .15s;margin-top:.5rem;white-space:nowrap}
.calc-add-other-btn:hover{border-color:var(--navy);color:var(--navy)}
.calc-remove-btn{background:none;border:none;color:var(--red);cursor:pointer;padding:4px;border-radius:4px;display:flex;align-items:center;justify-content:center}
.calc-remove-btn:hover{background:#fef3f5}
.calc-remove-btn svg{width:15px;height:15px}
.calc-reset-btn{display:inline-flex;align-items:center;gap:.4rem;background:none;border:1.5px solid var(--mid);border-radius:6px;padding:9px 16px;font-family:'Oswald',sans-serif;font-size:.74rem;font-weight:600;letter-spacing:.07em;text-transform:uppercase;color:var(--sub);cursor:pointer;transition:all .15s;margin-top:1rem;white-space:nowrap}
.calc-reset-btn:hover{border-color:var(--red);color:var(--red)}
/* SAVED BUDGET CARDS */
/* TEAM FINANCIALS */
.fin-toggle-group{display:flex;gap:.75rem;flex-wrap:wrap;margin-top:.3rem}
.fin-toggle{display:flex;align-items:center;gap:.5rem;background:var(--light);border:1.5px solid var(--mid);border-radius:8px;padding:10px 16px;cursor:pointer;transition:all .15s,box-shadow .15s;user-select:none;font-size:.84rem;color:var(--sub);font-weight:600}
.fin-toggle.selected{background:var(--navy);border-color:var(--navy);color:var(--white)}.fin-toggle:hover:not(.selected){border-color:var(--navy);color:var(--navy)}
.fin-toggle svg{width:16px;height:16px;flex-shrink:0}
.fin-plan-preview{background:linear-gradient(135deg,var(--navy) 0%,#162845 100%);border-radius:8px;padding:1.4rem 1.6rem;margin-top:1.2rem}
.fin-plan-title{font-family:'Oswald',sans-serif;font-size:.85rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:rgba(255,255,255,.6);margin-bottom:1rem}
.fin-plan-row{display:flex;align-items:center;justify-content:space-between;padding:.5rem 0;border-bottom:1px solid rgba(255,255,255,.07)}
.fin-plan-row:last-child{border-bottom:none}
.fin-plan-month{font-size:.82rem;color:rgba(255,255,255,.75)}
.fin-plan-amount{font-family:'Oswald',sans-serif;font-size:.95rem;font-weight:700;color:var(--white)}
.fin-plan-empty{color:rgba(255,255,255,.4);font-size:.84rem;text-align:center;padding:1rem}
.ar-table{width:100%;border-collapse:collapse;font-size:.83rem}
.ar-table thead tr{background:var(--navy)}
.ar-table thead th{padding:10px 14px;text-align:left;font-family:'Oswald',sans-serif;font-size:.7rem;font-weight:600;color:var(--white);letter-spacing:.1em;text-transform:uppercase;white-space:nowrap}
.ar-table tbody tr{border-bottom:1px solid var(--mid);transition:background .12s}
.ar-table tbody tr:last-child{border-bottom:none}
.ar-table tbody tr:hover{background:var(--light)}
.ar-table td{padding:10px 14px;vertical-align:middle;font-size:.82rem}
.ar-table td:first-child{font-weight:600;color:var(--navy)}
.ar-status{display:inline-block;padding:3px 10px;border-radius:20px;font-family:'Oswald',sans-serif;font-size:.62rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.ar-status.paid{background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0}
.ar-status.partial{background:#fffbea;color:#92400e;border:1px solid #fde68a}
.ar-status.pending{background:#fef3f5;color:var(--red);border:1px solid #f5c6cb}
.ar-mark-btn{display:inline-flex;align-items:center;gap:4px;background:none;border:1.5px solid var(--mid);border-radius:5px;padding:5px 10px;font-family:'Oswald',sans-serif;font-size:.62rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--navy);cursor:pointer;transition:all .15s;white-space:nowrap}
.ar-mark-btn:hover{background:var(--navy);color:var(--white);border-color:var(--navy)}
.ar-mark-btn svg{width:12px;height:12px}
.fin-summary-bar{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:1rem;margin-bottom:1.4rem}
.fin-stat{background:var(--white);border:1.5px solid var(--mid);border-radius:8px;padding:1rem 1.2rem}
.fin-stat-label{font-size:.65rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.4rem}
.fin-stat-value{font-family:'Oswald',sans-serif;font-size:1.3rem;font-weight:700;color:var(--navy)}
.fin-stat-value.green{color:#16a34a}
.fin-stat-value.red{color:var(--red)}
.plan-detail-wrap{display:flex;flex-direction:column;gap:.3rem;margin-top:.4rem}
.plan-detail-item{display:flex;align-items:center;justify-content:space-between;font-size:.75rem;padding:4px 8px;border-radius:4px;background:var(--light)}
.plan-detail-item.paid-item{background:#f0fdf4;color:#16a34a}
.plan-detail-check{width:14px;height:14px;border:1.5px solid var(--mid);border-radius:3px;cursor:pointer;accent-color:var(--navy)}
.no-ar-state{text-align:center;padding:2.5rem;color:var(--sub);font-size:.88rem}

.budget-card{background:var(--light);border:1.5px solid var(--mid);border-radius:10px;padding:1.1rem 1.3rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;transition:box-shadow .15s}
.budget-card:hover{box-shadow:0 4px 16px rgba(0,0,0,.08)}
.budget-card-info{flex:1;min-width:0}
.budget-card-date{font-size:.7rem;color:var(--sub);letter-spacing:.08em;text-transform:uppercase;margin-bottom:.3rem}
.budget-card-players{font-family:'Oswald',sans-serif;font-size:.82rem;font-weight:600;color:var(--navy);margin-bottom:.2rem}
.budget-card-total{font-family:'Oswald',sans-serif;font-size:1.15rem;font-weight:700;color:var(--red)}
.budget-card-fee{font-size:.78rem;color:var(--sub);margin-top:.2rem}
.budget-card-actions{display:flex;gap:.5rem;flex-shrink:0}
.budget-view-btn{display:inline-flex;align-items:center;gap:.35rem;background:var(--navy);color:var(--white);border:none;border-radius:6px;padding:7px 14px;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:background .15s}
.budget-view-btn:hover{background:#162845}
.budget-view-btn svg{width:13px;height:13px}
.budget-del-btn{display:inline-flex;align-items:center;gap:.35rem;background:none;border:1.5px solid #f5c6cb;color:var(--red);border-radius:6px;padding:7px 12px;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:all .15s}
.budget-del-btn:hover{background:var(--red);color:var(--white);border-color:var(--red)}
.budget-del-btn svg{width:13px;height:13px}
.budget-cards-list{display:flex;flex-direction:column;gap:.75rem}
/* BUDGET VIEW MODAL */
.budget-view-overlay{position:fixed;inset:0;background:rgba(10,22,40,.55);backdrop-filter:blur(4px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:1rem;opacity:0;pointer-events:none;transition:opacity .25s}
.budget-view-overlay.open{opacity:1;pointer-events:all}
.budget-view-modal{background:var(--white);border-radius:8px;box-shadow:0 20px 60px rgba(0,0,0,.25);width:100%;max-width:600px;max-height:90vh;display:flex;flex-direction:column;transform:translateY(20px) scale(.97);transition:transform .28s cubic-bezier(.4,0,.2,1);overflow:hidden}
.budget-view-overlay.open .budget-view-modal{transform:translateY(0) scale(1)}
.budget-view-head{background:var(--navy);padding:1rem 1.4rem;display:flex;align-items:center;justify-content:space-between}
.budget-view-head h3{font-family:'Oswald',sans-serif;font-size:1rem;font-weight:700;color:var(--white);text-transform:uppercase;letter-spacing:.08em}
.budget-view-body{overflow-y:auto;padding:1.4rem 1.5rem}
.budget-detail-table{width:100%;border-collapse:collapse;font-size:.84rem}
.budget-detail-table tr{border-bottom:1px solid var(--mid)}
.budget-detail-table tr:last-child{border-bottom:none}
.budget-detail-table td{padding:9px 12px;vertical-align:middle}
.budget-detail-table td:first-child{color:var(--sub);font-size:.78rem}
.budget-detail-table td:last-child{text-align:right;font-weight:600;color:var(--navy)}
.budget-detail-table tr.highlight td{background:var(--light);font-weight:700}
.budget-detail-table tr.highlight td:last-child{color:var(--red);font-size:1rem}
.budget-detail-table tr.grand td{background:linear-gradient(135deg,var(--navy) 0%,#162845 100%);color:var(--white)}
.budget-detail-table tr.grand td:last-child{color:#ffd700;font-size:1.1rem}
.budget-card{background:var(--white);border:1.5px solid var(--mid);border-radius:10px;padding:1.2rem 1.3rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;transition:box-shadow .15s,border-color .15s}
.budget-card:hover{box-shadow:0 4px 18px rgba(0,0,0,.08);border-color:#c8d0dc}
.budget-card-date{font-family:'Oswald',sans-serif;font-size:.82rem;font-weight:600;color:var(--sub);letter-spacing:.06em;text-transform:uppercase;margin-bottom:.3rem}
.budget-card-players{font-size:.85rem;color:var(--navy);font-weight:600;margin-bottom:.2rem}
.budget-card-total{font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:var(--navy);margin-bottom:.2rem}
.budget-card-fee{font-size:.8rem;color:var(--sub)}
.budget-card-actions{display:flex;flex-direction:column;gap:.5rem;flex-shrink:0}
.budget-view-btn{display:inline-flex;align-items:center;gap:5px;background:var(--navy);color:var(--white);border:none;border-radius:6px;padding:8px 16px;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:background .15s;white-space:nowrap}
.budget-view-btn:hover{background:var(--red)}
.budget-view-btn svg{width:13px;height:13px}
.budget-del-btn{display:inline-flex;align-items:center;gap:5px;background:none;border:1.5px solid #f5c6cb;border-radius:6px;padding:6px 14px;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--red);cursor:pointer;transition:all .15s;white-space:nowrap}
.budget-del-btn:hover{background:var(--red);color:var(--white);border-color:var(--red)}
.budget-del-btn svg{width:13px;height:13px}
.budget-publish-btn{display:inline-flex;align-items:center;gap:5px;background:#1d4ed8;border:none;border-radius:6px;padding:8px 16px;font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#fff;cursor:pointer;transition:background .15s;white-space:nowrap}
.budget-publish-btn:hover{background:#1e40af}
.budget-publish-btn svg{width:13px;height:13px}
.budget-cards-list{display:flex;flex-direction:column;gap:.85rem}
.budget-detail-table{width:100%;border-collapse:collapse;font-size:.84rem}
.budget-detail-table tr{border-bottom:1px solid var(--mid)}
.budget-detail-table tr:last-child{border-bottom:none}
.budget-detail-table td{padding:9px 12px;vertical-align:middle}
.budget-detail-table td:first-child{color:var(--sub);font-size:.8rem}
.budget-detail-table td:last-child{font-weight:600;color:var(--navy);text-align:right}
.budget-detail-table tr.highlight td{background:#f0fdf4;color:#16a34a;font-weight:700;font-size:.95rem}
.budget-detail-table tr.grand td{background:var(--navy);color:var(--white);font-weight:700;font-size:1rem}
@media(max-width:700px){.form-grid-2,.form-grid-3{grid-template-columns:1fr}.page-header-inner{flex-direction:column;align-items:flex-start}.section-tabs{gap:.3rem}.section-tab{padding:5px 9px;font-size:.68rem}}

/* BUDGET */
.budget-section-label{font-family:'Oswald',sans-serif;font-size:.72rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--white);background:var(--navy);padding:6px 14px;border-radius:4px;display:block;margin:1.2rem 0 .9rem}
.budget-section-label:first-child{margin-top:0}
.budget-row{display:grid;grid-template-columns:1fr 1fr;gap:.7rem 1.2rem;margin-bottom:.7rem;align-items:end}
.budget-row.single{grid-template-columns:1fr}
.budget-row.triple{grid-template-columns:1fr 1fr 1fr}
.budget-field{display:flex;flex-direction:column;gap:.3rem}
.budget-label{font-size:.63rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub)}
.budget-input{border:1.5px solid var(--mid);border-radius:7px;padding:9px 12px;font-size:.86rem;font-family:'Open Sans',sans-serif;color:var(--text);background:var(--white);outline:none;transition:border-color .15s;width:100%}
.budget-input:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(200,16,46,.08)}
.budget-input[readonly]{background:#f9fafb;color:var(--navy);font-weight:700;cursor:default}
.budget-totals{background:linear-gradient(135deg,var(--navy) 0%,#162845 100%);border-radius:8px;padding:1.2rem 1.4rem;margin-top:1.4rem}
.budget-totals-title{font-family:'Oswald',sans-serif;font-size:.82rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:rgba(255,255,255,.6);margin-bottom:.9rem}
.budget-total-row{display:flex;align-items:center;justify-content:space-between;padding:.45rem 0;border-bottom:1px solid rgba(255,255,255,.08)}
.budget-total-row:last-child{border-bottom:none;padding-top:.8rem;margin-top:.4rem}
.budget-total-label{font-size:.8rem;color:rgba(255,255,255,.7)}
.budget-total-value{font-family:'Oswald',sans-serif;font-size:.95rem;font-weight:700;color:var(--white)}
.budget-total-row.grand{border-top:2px solid rgba(255,255,255,.2)}
.budget-total-row.grand .budget-total-label{font-size:.88rem;color:var(--white);font-weight:700}
.budget-total-row.grand .budget-total-value{font-size:1.15rem;color:#f5c518}
.budget-player-fee{background:#f0fdf4;border:1.5px solid #bbf7d0;border-radius:8px;padding:1rem 1.2rem;margin-top:1rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem}
.budget-player-fee-label{font-size:.8rem;color:#166534;font-weight:600}
.budget-player-fee-value{font-family:'Oswald',sans-serif;font-size:1.3rem;font-weight:700;color:#15803d}
.budget-list-item{background:var(--light);border:1.5px solid var(--mid);border-radius:8px;padding:1rem 1.2rem;margin-bottom:.75rem}
.budget-list-item-header{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.budget-list-name{font-family:'Oswald',sans-serif;font-size:.95rem;font-weight:700;color:var(--navy)}
.budget-list-meta{font-size:.78rem;color:var(--sub);margin-top:.3rem}
.budget-list-fee{font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:var(--red)}
.budget-list-actions{display:flex;gap:.4rem;flex-shrink:0}

/* ── COACH FINANCIAL DASHBOARD ── */
.cfd-metrics{display:flex;flex-wrap:wrap;justify-content:center;gap:1rem;max-width:1060px;margin:0 auto 1.4rem}
.cfd-metrics .cfd-metric{flex:0 0 calc(33.333% - 0.75rem);min-width:220px}
.cfd-metric{background:var(--white);border-radius:8px;padding:1.2rem 1.3rem;box-shadow:0 2px 12px rgba(0,0,0,.07);border:1px solid var(--mid);display:flex;gap:.9rem;align-items:flex-start;transition:all .2s}
.cfd-metric:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.1)}
.cfd-metric.budget{background:linear-gradient(135deg,var(--navy) 0%,#162845 100%);border-color:var(--navy);position:relative;overflow:hidden}
.cfd-metric.budget::after{content:'';position:absolute;right:-30px;bottom:-30px;width:110px;height:110px;border-radius:50%;background:rgba(200,16,46,.15);pointer-events:none}
.cfd-metric.alert{background:linear-gradient(135deg,#fef3f5 0%,#fde8ec 100%);border-color:#f5c6cb}
.cfd-chart-standalone{max-width:600px;margin:0 auto 1.8rem;background:var(--white);border-radius:8px;padding:1.4rem 1.5rem;box-shadow:0 2px 12px rgba(0,0,0,.07);border:1px solid var(--mid)}
.cfd-micon{width:46px;height:46px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;flex-shrink:0;background:rgba(10,22,40,.08);position:relative;z-index:1}
.budget .cfd-micon{background:rgba(255,255,255,.15)}
.cfd-micon.ic{background:rgba(59,130,246,.12)}
.cfd-micon.col{background:rgba(22,163,74,.12)}
.cfd-micon.bal{background:rgba(200,16,46,.12)}
.cfd-micon.ok{background:rgba(22,163,74,.12)}
.cfd-micon.red{background:rgba(200,16,46,.12)}
.cfd-micon.dl{background:rgba(180,83,9,.12)}
.cfd-mbody{display:flex;flex-direction:column;gap:.25rem;flex:1;position:relative;z-index:1;min-width:0}
.cfd-mlabel{font-size:.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub)}
.budget .cfd-mlabel{color:rgba(255,255,255,.7)}
.cfd-mval{font-family:'Oswald',sans-serif;font-size:1.7rem;font-weight:700;color:var(--navy);line-height:1.1}
.budget .cfd-mval{color:#fff}
.cfd-msub{font-size:.78rem;color:var(--sub)}
.budget .cfd-msub{color:rgba(255,255,255,.7)}
.cfd-pie-wrap{width:180px;height:180px;margin:.4rem auto;position:relative}
.cfd-seg{cursor:pointer;pointer-events:stroke;transition:filter .15s}
.cfd-seg:hover{filter:brightness(1.15)}
.cfd-pie-tt{position:absolute;background:var(--navy);color:#fff;padding:7px 11px;border-radius:6px;box-shadow:0 4px 14px rgba(0,0,0,.22);pointer-events:none;opacity:0;transition:opacity .12s;z-index:10;white-space:nowrap;min-width:130px}
.cfd-pie-tt.show{opacity:1}
.cfd-pie-tt .ptt-lbl{display:block;font-size:.6rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:rgba(255,255,255,.55);margin-bottom:2px}
.cfd-pie-tt .ptt-amt{font-family:'Oswald',sans-serif;font-size:1rem;font-weight:700}
.cfd-pie-tt .ptt-pct{color:rgba(255,255,255,.6);font-size:.74rem;margin-left:.3rem}
.cfd-legend{display:flex;justify-content:center;gap:1.2rem;margin-top:.4rem;flex-wrap:wrap}
.cfd-leg-item{display:flex;align-items:center;gap:.4rem;font-size:.78rem;color:var(--text)}
.cfd-leg-dot{width:10px;height:10px;border-radius:50%}
.cfd-section{background:var(--white);border-radius:8px;border:1px solid var(--mid);overflow:hidden;margin-bottom:1.4rem;box-shadow:0 2px 10px rgba(0,0,0,.06);max-width:1050px;margin-left:auto;margin-right:auto}
.cfd-section-head{background:var(--red);padding:12px 22px;display:flex;justify-content:space-between;align-items:center;gap:.75rem;flex-wrap:wrap}
.cfd-section-head h3{font-family:'Oswald',sans-serif;font-size:.95rem;font-weight:700;color:#fff;letter-spacing:.12em;text-transform:uppercase}
.cfd-section-body{padding:1.4rem 1.5rem}
.cfd-tbl{width:100%;border-collapse:collapse;font-size:.84rem}
.cfd-tbl thead tr{background:var(--navy)}
.cfd-tbl th{padding:9px 13px;text-align:left;font-family:'Oswald',sans-serif;font-size:.68rem;font-weight:700;color:#fff;letter-spacing:.1em;text-transform:uppercase;white-space:nowrap}
.cfd-tbl td{padding:10px 13px;border-bottom:1px solid var(--mid);font-size:.84rem;vertical-align:middle}
.cfd-tbl tbody tr:last-child td{border-bottom:none}
.cfd-tbl tbody tr:hover{background:var(--light)}
.cfd-tbl .t-name{font-weight:700;color:var(--navy)}
.cfd-tbl .t-paid{color:#16a34a;font-weight:700;font-family:'Oswald',sans-serif}
.cfd-tbl .t-bal{color:var(--red);font-weight:700;font-family:'Oswald',sans-serif}
.cfd-sbadge{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-family:'Oswald',sans-serif;font-size:.64rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;border:1px solid transparent}
.cfd-sbadge.paid{background:#f0fdf4;color:#15803d;border-color:#bbf7d0}
.cfd-sbadge.partial{background:#fffbea;color:#92400e;border-color:#fde68a}
.cfd-sbadge.unpaid{background:#fef3f5;color:var(--red);border-color:#f5c6cb}
.cfd-controls{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.cfd-search{display:flex;align-items:center;gap:.4rem;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);border-radius:6px;padding:5px 11px}
.cfd-search input{border:none;background:none;outline:none;color:#fff;font-family:'Source Sans 3',sans-serif;font-size:.82rem;width:160px}
.cfd-search input::placeholder{color:rgba(255,255,255,.6)}
.cfd-filter{padding:5px 11px;border:1px solid rgba(255,255,255,.25);border-radius:6px;background:rgba(255,255,255,.15);font-family:'Source Sans 3',sans-serif;font-size:.8rem;color:#fff;cursor:pointer;outline:none}
.cfd-pag{display:flex;align-items:center;justify-content:space-between;gap:.6rem;padding:.7rem .9rem;border-top:1px solid var(--mid);flex-wrap:wrap}
.cfd-pag-info{font-size:.78rem;color:var(--sub)}
.cfd-pag-btns{display:flex;align-items:center;gap:.5rem}
#cfd-content{max-width:1400px;padding:0 .5rem}
.cfd-pbtn{display:inline-flex;align-items:center;justify-content:center;min-width:30px;height:28px;padding:0 8px;border:1.5px solid var(--mid);border-radius:5px;background:var(--white);font-size:.78rem;font-weight:600;color:var(--text);cursor:pointer;transition:all .12s}
.cfd-pbtn:hover:not(:disabled){border-color:var(--navy);color:var(--navy)}
.cfd-pbtn.cur{border-color:var(--red);color:var(--red);cursor:default}
.cfd-pbtn:disabled{color:var(--mid);cursor:not-allowed}
@media(max-width:700px){.cfd-metrics .cfd-metric{flex:0 0 calc(50% - 0.5rem)}}
@media(max-width:480px){.cfd-metrics .cfd-metric{flex:0 0 100%}}
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flatpickr/4.6.13/flatpickr.min.css">
<style>
.flatpickr-calendar { font-family: 'Open Sans', sans-serif; }
.flatpickr-day.selected, .flatpickr-day.selected:hover { background: var(--navy); border-color: var(--navy); }
.flatpickr-day:hover { background: var(--light); }
.flatpickr-months .flatpickr-month { background: var(--navy); color: var(--white); }
.flatpickr-current-month .flatpickr-monthDropdown-months { background: var(--navy); color: var(--white); }
.flatpickr-weekday { color: var(--navy); font-weight: 600; }
.flatpickr-prev-month svg, .flatpickr-next-month svg { fill: var(--white); }
.flatpickr-prev-month:hover svg, .flatpickr-next-month:hover svg { fill: var(--red); }
.date-input-wrap { position: relative; }
.date-input-wrap .cal-icon { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); pointer-events: none; color: var(--sub); }
.date-input-wrap .cal-icon svg { width: 16px; height: 16px; }
.date-input-wrap .field-input { padding-right: 38px; cursor: pointer; }
.date-input-wrap .field-input::-webkit-calendar-picker-indicator { display: none; }
.flatpickr-input { cursor: pointer !important; }
</style>
</head>
<body>
<div id="navbar-root"></div>
<script>
  fetch('navbar.html')
    .then(r => r.text())
    .then(html => {
      const root = document.getElementById('navbar-root');
      root.innerHTML = html;
      root.querySelectorAll('script').forEach(function(oldScript) {
        const newScript = document.createElement('script');
        newScript.textContent = oldScript.textContent;
        document.head.appendChild(newScript);
      });
    });
</script>
<div class="page-header">
  <div class="page-header-inner">
    <div class="header-left">
      <h1 id="dash-title">Coach Dashboard</h1>
      <p id="dash-sub">Loading…</p>
    </div>
    <button class="logout-btn" onclick="handleLogout()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      Logout
    </button>
  </div>
</div>
<div class="main" id="dash-main">
  <div class="loading-state"><div class="spinner"></div>Loading your dashboard…</div>
</div>
<script>
'use strict';

// Prevent number input values from changing on scroll, but allow page scrolling
document.addEventListener('wheel', (e) => {
  if (e.target.type === 'number') {
    // Blur the input so the scroll goes to the page instead
    e.target.blur();
  }
}, { passive: true });

const API_BASE = 'https://backend-baseball-inky.vercel.app';

// ── ADMIN IMPERSONATION (Option 3) ──
const _params     = new URLSearchParams(window.location.search);
const _urlToken   = _params.get('adminToken');
const _urlCoachId = _params.get('adminCoachId');
if (_urlToken) {
  sessionStorage.setItem('admin_impersonation_token',    _urlToken);
  sessionStorage.setItem('admin_impersonation_coach_id', _urlCoachId);
  window.history.replaceState({}, '', 'coach-dashboard.html');
}
const isAdminView = !!sessionStorage.getItem('admin_impersonation_token');
const token = isAdminView
  ? sessionStorage.getItem('admin_impersonation_token')
  : localStorage.getItem('coach_token');
if (!token) window.location.href = 'coach-auth.html';

const authH = () => ({ 'Content-Type':'application/json', 'Authorization':`Bearer ${token}` });
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function showMsg(id,text,type){
  const el=document.getElementById(id); if(!el) return;
  el.textContent=text; el.className='msg '+type;
  setTimeout(()=>{ el.className='msg'; },4000);
}
function setLoading(btnId,textId,loading,label){
  const btn=document.getElementById(btnId); if(!btn) return;
  document.getElementById(textId).innerHTML=loading?'<span class="btn-spinner"></span>':label;
  btn.disabled=loading;
}
function handleLogout(){
  if (isAdminView) {
    sessionStorage.removeItem('admin_impersonation_token');
    sessionStorage.removeItem('admin_impersonation_coach_id');
    window.close();
  } else {
    localStorage.removeItem('coach_token');
    localStorage.removeItem('coach_id');
    window.location.href='coach-auth.html';
  }
}
let _pollInterval = null;
let _activePanel  = 'profile';

function switchPanel(name){
  document.querySelectorAll('.dash-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.section-tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
  _activePanel = name;

  // Fetch immediately on tab switch
  if (name === 'roster')   loadDashRoster();
  if (name === 'schedule') loadDashSchedule();
  if (name === 'tryouts')  loadTryouts();
  if (name === 'tryreg')   loadTryoutRegs();
  if (name === 'financials') loadFinancials();
  if (name === 'budget')   loadBudgetsLocal();
  if (name === 'findashboard') cfdLoad();

  // Clear old poll, start new one for live tabs
  clearInterval(_pollInterval);
  const liveTabs = { roster: loadDashRoster, schedule: loadDashSchedule, tryouts: loadTryouts };
  if (liveTabs[name]) {
    _pollInterval = setInterval(liveTabs[name], 15000);
  }
}

// Stop polling when tab is hidden, resume when visible
document.addEventListener('visibilitychange', () => {
  clearInterval(_pollInterval);
  if (document.visibilityState === 'visible') {
    const liveTabs = { roster: loadDashRoster, schedule: loadDashSchedule, tryouts: loadTryouts };
    if (liveTabs[_activePanel]) {
      liveTabs[_activePanel]();
      _pollInterval = setInterval(liveTabs[_activePanel], 15000);
    }
  }
});



/* ── LOAD ── */
async function loadDashboard(){
  try {
    const res=await fetch(`${API_BASE}/api/coach/me`,{headers:authH()});
    if(res.status===401){ handleLogout(); return; }
    const {coach}=await res.json();
    if (coach._id) localStorage.setItem('coach_id', coach._id);
    renderDashboard(coach);
  } catch(err){
    document.getElementById('dash-main').innerHTML='<div class="card"><div class="card-body" style="text-align:center;color:var(--red);padding:3rem">'+esc(err.message)+'</div></div>';
  }
}

/* ── RENDER ── */
function renderDashboard(coach){
  document.getElementById('dash-title').textContent=coach.firstName+' '+coach.lastName;
  document.getElementById('dash-sub').textContent='Head Coach — '+coach.teamName;

  const headPhotoHtml = coach.image
    ? '<img src="'+esc(coach.image)+'" id="p-photo-img" style="width:100%;height:100%;object-fit:cover;border-radius:50%">'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>';

  const a1PhotoHtml = (coach.assistant1 && coach.assistant1.image)
    ? '<img src="'+esc(coach.assistant1.image)+'" id="a1-photo-img" style="width:100%;height:100%;object-fit:cover;border-radius:50%">'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>';

  const a2PhotoHtml = (coach.assistant2 && coach.assistant2.image)
    ? '<img src="'+esc(coach.assistant2.image)+'" id="a2-photo-img" style="width:100%;height:100%;object-fit:cover;border-radius:50%">'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>';

  document.getElementById('dash-main').innerHTML=`
    <div class="welcome-banner">
      <div class="welcome-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg></div>
      <div class="welcome-text">
        <h2>Welcome back, ${esc(coach.firstName)}!</h2>
        <p>Team: ${esc(coach.teamName)}</p>
      </div>
    </div>

    <div class="section-tabs">
      <button class="section-tab active" id="tab-profile" onclick="switchPanel('profile')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
        My Profile
      </button>
      <button class="section-tab" id="tab-teamdetails" onclick="switchPanel('teamdetails')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>
        Team Details
      </button>
      <button class="section-tab" id="tab-assistants" onclick="switchPanel('assistants')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
        Assistant Coaches
      </button>
      <button class="section-tab" id="tab-tryouts" onclick="switchPanel('tryouts')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>
        Add Tryout
      </button>
      <button class="section-tab" id="tab-roster" onclick="switchPanel('roster')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
        Team Roster
      </button>
      <button class="section-tab" id="tab-schedule" onclick="switchPanel('schedule')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/><path d="M8 14h.01M12 14h.01M16 14h.01M8 18h.01M12 18h.01"/></svg>
        Schedule
      </button>
      <button class="section-tab" id="tab-tryreg" onclick="switchPanel('tryreg')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
        Tryout Registrations
      </button>
      <button class="section-tab" id="tab-financials" onclick="switchPanel('financials')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>
        Team Financials
      </button>
      <button class="section-tab" id="tab-calculator" onclick="switchPanel('calculator')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="2" width="16" height="20" rx="2"/><line x1="8" y1="6" x2="16" y2="6"/><line x1="8" y1="10" x2="10" y2="10"/><line x1="14" y1="10" x2="16" y2="10"/><line x1="8" y1="14" x2="10" y2="14"/><line x1="14" y1="14" x2="16" y2="14"/><line x1="8" y1="18" x2="10" y2="18"/><line x1="14" y1="18" x2="16" y2="18"/></svg>
        Budget Calculator
      </button>
      <button class="section-tab" id="tab-findashboard" onclick="switchPanel('findashboard')" style="background:var(--red);border-color:var(--red);color:#fff;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
        Financial Dashboard
      </button>

    </div>

    <!-- MY PROFILE -->
    <div class="dash-panel active" id="panel-profile">
      <div class="card">
        <div class="card-header">My Profile</div>
        <div class="card-body">
          <div class="info-note">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Your profile is displayed publicly on your team page as the Head Coach.
          </div>
          <div class="msg" id="msg-profile"></div>
          <div class="photo-upload-wrap">
            <div class="photo-preview" id="p-photo-preview">${headPhotoHtml}</div>
            <div class="photo-upload-right">
              <span class="field-label">Profile Photo</span>
              <input type="file" accept="image/*" class="hidden-file" id="p-photo-input" onchange="handlePhotoUpload(this,'p-photo-preview','p-photo-status','p-photo-img')">
              <div class="photo-btn-row" id="p-photo-btn-row">
                ${coach.image ? `
                  <button class="photo-edit-btn edit" onclick="document.getElementById('p-photo-input').click()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    Edit Photo
                  </button>
                  <button class="photo-edit-btn delete" onclick="deletePhoto('head','p-photo-preview','p-photo-status','p-photo-btn-row')">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
                    Delete
                  </button>
                ` : `
                  <button class="photo-edit-btn edit" onclick="document.getElementById('p-photo-input').click()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    Upload Photo
                  </button>
                `}
              </div>
              <div class="photo-upload-hint">JPG or PNG, max 5MB</div>
              <div class="photo-uploading" id="p-photo-status"></div>
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">First Name</label>
              <input class="field-input" type="text" id="p-firstname" value="${esc(coach.firstName)}" placeholder="First Name">
            </div>
            <div class="field-group">
              <label class="field-label">Last Name</label>
              <input class="field-input" type="text" id="p-lastname" value="${esc(coach.lastName)}" placeholder="Last Name">
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">Public Email</label>
              <input class="field-input" type="email" id="p-email-pub" value="${esc(coach.emailPublic||'')}" placeholder="Shown on team page">
            </div>
            <div class="field-group">
              <label class="field-label">Public Cell</label>
              <input class="field-input" type="tel" id="p-phone-pub" value="${esc(coach.phonePublic||'')}" placeholder="(615) 000-0000">
            </div>
          </div>
          <div class="field-group">
            <label class="field-label">Bio</label>
            <textarea class="field-textarea" id="p-bio" placeholder="Write a short coaching bio…">${esc(coach.bio||'')}</textarea>
          </div>
          <button class="save-btn" id="save-profile-btn" onclick="saveProfile()">
            <span id="save-profile-txt">Save Profile</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </button>
        </div>
      </div>
    </div>

    <!-- TEAM DETAILS -->
    <div class="dash-panel" id="panel-teamdetails">
      <div class="card">
        <div class="card-header">Team Details</div>
        <div class="card-body">
          <div class="info-note">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            This info is shown in the Team Details section on your team page and on the team directory map.
          </div>
          <div class="msg" id="msg-teamdetails"></div>
          <div class="field-group">
            <label class="field-label">Team Name</label>
            <input class="field-input" type="text" id="td-teamname" value="${esc(coach.teamName)}" placeholder="Team Name">
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">Age Group</label>
              <input class="field-input" type="text" id="td-agegroup" value="${esc(coach.ageGroup||'')}" placeholder="e.g. 17U">
            </div>
            <div class="field-group">
              <label class="field-label">State</label>
              <input class="field-input" type="text" id="td-state" value="${esc(coach.state||'')}" placeholder="e.g. TN" maxlength="2">
            </div>
          </div>
          <div class="field-group">
            <label class="field-label">Team Details</label>
            <textarea class="field-textarea" id="td-details" placeholder="Add any additional team details, description, or notes here…">${esc(coach.teamDetails||'')}</textarea>
          </div>
          <hr class="section-divider">
          <div class="toggle-row">
            <div class="toggle-label-wrap">
              <span class="toggle-label-main">Roster Registration Button</span>
              <span class="toggle-label-sub">Enable or disable the Accept Roster Invitation button on your public team page</span>
            </div>
            <div style="display:flex;align-items:center;gap:.5rem">
              <span class="toggle-status ${coach.registerEnabled!==false?'on':'off'}" id="td-register-status">${coach.registerEnabled!==false?'Enabled':'Disabled'}</span>
              <label class="toggle-switch">
                <input type="checkbox" id="td-register-enabled" ${coach.registerEnabled!==false?'checked':''} onchange="updateRegisterStatus()">
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>
          <button class="save-btn" id="save-td-btn" onclick="saveTeamDetails()">
            <span id="save-td-txt">Save Team Details</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </button>
        </div>
      </div>
    </div>

    <!-- ASSISTANTS -->
    <div class="dash-panel" id="panel-assistants">
      <div class="card">
        <div class="card-header">Assistant Coaches</div>
        <div class="card-body">
          <div class="info-note">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Add up to 2 assistant coaches. Leave Name blank to hide from the team page.
          </div>
          <div class="msg" id="msg-assistants"></div>
          <div class="asst-label">Assistant Coach 1</div>
          <div class="asst-photo-wrap">
            <div class="asst-photo-preview" id="a1-photo-preview">${a1PhotoHtml}</div>
            <div class="photo-upload-right">
              <span class="field-label">Assistant 1 Photo</span>
              <input type="file" accept="image/*" class="hidden-file" id="a1-photo-input" onchange="handleAsstPhotoUpload(this,'a1-photo-preview','a1-photo-status','a1-photo-img','a1-image-url','asst1','a1-photo-btn-row')">
              <div class="photo-btn-row" id="a1-photo-btn-row">
                ${(coach.assistant1&&coach.assistant1.image) ? `
                  <button class="photo-edit-btn edit" onclick="document.getElementById('a1-photo-input').click()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    Edit Photo
                  </button>
                  <button class="photo-edit-btn delete" onclick="deletePhoto('asst1','a1-photo-preview','a1-photo-status','a1-photo-btn-row','a1-image-url')">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
                    Delete
                  </button>
                ` : `
                  <button class="photo-edit-btn edit" onclick="document.getElementById('a1-photo-input').click()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    Upload Photo
                  </button>
                `}
              </div>
              <div class="photo-uploading" id="a1-photo-status"></div>
            </div>
          </div>
          <input type="hidden" id="a1-image-url" value="${esc((coach.assistant1&&coach.assistant1.image)||'')}">
          <div class="form-grid-2">
            <div class="field-group"><label class="field-label">Full Name</label><input class="field-input" type="text" id="a1-name" value="${esc((coach.assistant1&&coach.assistant1.name)||'')}" placeholder="Full Name"></div>
            <div class="field-group"><label class="field-label">Role / Title</label><input class="field-input" type="text" id="a1-role" value="${esc((coach.assistant1&&coach.assistant1.role)||'Assistant Coach')}" placeholder="e.g. Pitching Coach"></div>
          </div>
          <div class="form-grid-2">
            <div class="field-group"><label class="field-label">Email</label><input class="field-input" type="email" id="a1-email" value="${esc((coach.assistant1&&coach.assistant1.email)||'')}" placeholder="Email address"></div>
            <div class="field-group"><label class="field-label">Cell</label><input class="field-input" type="tel" id="a1-cell" value="${esc((coach.assistant1&&coach.assistant1.cell)||'')}" placeholder="(615) 000-0000"></div>
          </div>
          <div class="field-group"><label class="field-label">Bio</label><textarea class="field-textarea" id="a1-bio" placeholder="Short bio…">${esc((coach.assistant1&&coach.assistant1.bio)||'')}</textarea></div>
          <hr class="section-divider">
          <div class="asst-label">Assistant Coach 2</div>
          <div class="asst-photo-wrap">
            <div class="asst-photo-preview" id="a2-photo-preview">${a2PhotoHtml}</div>
            <div class="photo-upload-right">
              <span class="field-label">Assistant 2 Photo</span>
              <input type="file" accept="image/*" class="hidden-file" id="a2-photo-input" onchange="handleAsstPhotoUpload(this,'a2-photo-preview','a2-photo-status','a2-photo-img','a2-image-url','asst2','a2-photo-btn-row')">
              <div class="photo-btn-row" id="a2-photo-btn-row">
                ${(coach.assistant2&&coach.assistant2.image) ? `
                  <button class="photo-edit-btn edit" onclick="document.getElementById('a2-photo-input').click()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    Edit Photo
                  </button>
                  <button class="photo-edit-btn delete" onclick="deletePhoto('asst2','a2-photo-preview','a2-photo-status','a2-photo-btn-row','a2-image-url')">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
                    Delete
                  </button>
                ` : `
                  <button class="photo-edit-btn edit" onclick="document.getElementById('a2-photo-input').click()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    Upload Photo
                  </button>
                `}
              </div>
              <div class="photo-uploading" id="a2-photo-status"></div>
            </div>
          </div>
          <input type="hidden" id="a2-image-url" value="${esc((coach.assistant2&&coach.assistant2.image)||'')}">
          <div class="form-grid-2">
            <div class="field-group"><label class="field-label">Full Name</label><input class="field-input" type="text" id="a2-name" value="${esc((coach.assistant2&&coach.assistant2.name)||'')}" placeholder="Full Name"></div>
            <div class="field-group"><label class="field-label">Role / Title</label><input class="field-input" type="text" id="a2-role" value="${esc((coach.assistant2&&coach.assistant2.role)||'Assistant Coach')}" placeholder="e.g. Hitting Coach"></div>
          </div>
          <div class="form-grid-2">
            <div class="field-group"><label class="field-label">Email</label><input class="field-input" type="email" id="a2-email" value="${esc((coach.assistant2&&coach.assistant2.email)||'')}" placeholder="Email address"></div>
            <div class="field-group"><label class="field-label">Cell</label><input class="field-input" type="tel" id="a2-cell" value="${esc((coach.assistant2&&coach.assistant2.cell)||'')}" placeholder="(615) 000-0000"></div>
          </div>
          <div class="field-group"><label class="field-label">Bio</label><textarea class="field-textarea" id="a2-bio" placeholder="Short bio…">${esc((coach.assistant2&&coach.assistant2.bio)||'')}</textarea></div>
          <button class="save-btn" id="save-asst-btn" onclick="saveAssistants()">
            <span id="save-asst-txt">Save Assistants</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </button>
        </div>
      </div>
    </div>

    <!-- ROSTER -->
    <div class="dash-panel" id="panel-roster">
      <div class="card">
        <div class="card-header">Team Roster</div>
        <div class="roster-table-wrap">
          <table class="roster-mgmt-table">
            <thead>
              <tr>
                <th>Player</th><th>Jersey</th><th>Grad Year</th>
                <th>Position</th><th>HT/WT</th><th>City</th><th>State</th><th>Email</th><th>Cell</th><th>Actions</th>
              </tr>
            </thead>
            <tbody id="dash-roster-body">
              <tr><td colspan="10"><div class="empty-roster-dash">Loading roster…</div></td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- SCHEDULE -->
    <div class="dash-panel" id="panel-schedule">
      <div class="card">
        <div class="card-header">Add Game / Event</div>
        <div class="card-body">
          <div class="msg" id="msg-sched-add"></div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">Start Date</label>
              <div class="date-input-wrap"><input class="field-input" type="text" id="s-start-date" placeholder="e.g. June 14, 2026"><span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg></span></div>
            </div>
            <div class="field-group">
              <label class="field-label">End Date</label>
              <div class="date-input-wrap"><input class="field-input" type="text" id="s-end-date" placeholder="e.g. June 15, 2026"><span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg></span></div>
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">Event Name</label>
              <input class="field-input" type="text" id="s-event" placeholder="e.g. vs. Nashville Elite 17U">
            </div>
            <div class="field-group">
              <label class="field-label">City</label>
              <input class="field-input" type="text" id="s-city" placeholder="e.g. Nashville">
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">State</label>
              <input class="field-input" type="text" id="s-state" placeholder="e.g. TN" maxlength="2">
            </div>
          </div>
          <button class="save-btn" id="add-game-btn" onclick="addGame()">
            <span id="add-game-txt">Add to Schedule</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          </button>
        </div>
      </div>
      <div class="card">
        <div class="card-header">Team Schedule</div>
        <div class="sched-table-wrap">
          <table class="sched-mgmt-table">
            <thead>
              <tr>
                <th>Date</th><th>Event Name</th><th>City</th><th>State</th><th>Actions</th>
              </tr>
            </thead>
            <tbody id="dash-sched-body">
              <tr><td colspan="6"><div class="no-schedule-dash">Loading schedule…</div></td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TRYOUTS -->
    <div class="dash-panel" id="panel-tryouts">
      <div class="card">
        <div class="card-header">Create New Tryout</div>
        <div class="card-body">
          <div class="msg" id="msg-tryout-add"></div>
          <div class="form-grid-2">
            <div class="field-group"><label class="field-label">Date</label><div class="date-input-wrap"><input class="field-input" type="text" id="t-date" placeholder="e.g. June 10, 2026"><span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg></span></div></div>
            <div class="field-group">
              <label class="field-label">Time</label>
              <input type="hidden" id="t-time">
              <div style="display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:.5rem;">
                <div class="date-input-wrap">
                  <input class="field-input" type="text" id="t-time-start" placeholder="Start Time">
                  <span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></span>
                </div>
                <span style="color:var(--sub);font-size:.82rem;white-space:nowrap;font-weight:600;">to</span>
                <div class="date-input-wrap">
                  <input class="field-input" type="text" id="t-time-end" placeholder="End Time">
                  <span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></span>
                </div>
              </div>
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group"><label class="field-label">Location / Field Name</label><input class="field-input" type="text" id="t-location" placeholder="e.g. Westside Sports Complex"></div>
            <div class="field-group">
              <label class="field-label">Tryout Fee</label>
              <div id="t-fee-container">
                <select class="field-select" id="t-fee-type" onchange="toggleAddFeeAmount()">
                  <option value="free">Free</option>
                  <option value="fee">Fee</option>
                </select>
              </div>
            </div>
          </div>
          <div class="form-grid-2">
            <div class="field-group"><label class="field-label">City</label><input class="field-input" type="text" id="t-city" placeholder="e.g. Nashville"></div>
            <div class="field-group"><label class="field-label">State</label><input class="field-input" type="text" id="t-state" placeholder="e.g. TN" maxlength="2"></div>
          </div>
          <button class="save-btn" id="add-tryout-btn" onclick="addTryout()">
            <span id="add-tryout-txt">Add Tryout</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          </button>
        </div>
      </div>
      <div class="card">
        <div class="card-header">Scheduled Tryouts</div>
        <div class="card-body">
          <div class="msg" id="msg-tryout-list"></div>
          <div id="tryouts-list-wrap"><div class="loading-state" style="padding:1.5rem"><div class="spinner"></div></div></div>
        </div>
      </div>
    </div>

    <!-- BUDGET PANEL -->
    <div class="dash-panel" id="panel-tryreg">

      <div class="msg" id="msg-tryreg"></div>
      <div id="tryreg-cards-wrap" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1rem;margin-bottom:1.6rem">
        <div class="no-schedule-dash">Loading…</div>
      </div>
      <div id="tryreg-table-wrap" style="display:none">
        <div class="card">
          <div class="card-header" id="tryreg-table-heading">Registrations</div>
          <div style="overflow-x:auto">
            <table class="tryreg-table">
              <thead>
                <tr>
                  <th>Player Name</th><th>Contact Name</th><th>Email</th><th>Cell</th>
                  <th>Position(s)</th><th>Age</th><th>HT/WT</th><th>Completed By</th><th>Address</th><th>Payment</th>
                </tr>
              </thead>
              <tbody id="tryreg-body">
                <tr><td colspan="9"><div class="no-schedule-dash">Select a tryout above.</div></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- TEAM FINANCIALS PANEL -->
    <div class="dash-panel" id="panel-financials">

      <!-- SETUP CARD -->
      <div class="card" style="margin-bottom:1.4rem">
        <div class="card-header">Team Financial Setup</div>
        <div class="card-body">
          <div class="info-note">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Set up your team's payment model. Players will automatically receive a payment plan when they register.
          </div>
          <div class="msg" id="msg-financials"></div>

          <!-- Row 1: Fee + Deadline -->
          <div class="form-grid-2">
            <div class="field-group">
              <label class="field-label">Player Fee Amount</label>
              <div style="position:relative">
                <span style="position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--sub);font-size:.88rem;pointer-events:none">$</span>
                <input class="field-input" type="number" id="fin-fee" placeholder="e.g. 2000" min="0" style="padding-left:26px;background:#f4f6f9;cursor:not-allowed;color:var(--sub)" readonly>
              </div>
              <div style="font-size:.68rem;color:var(--sub);margin-top:.3rem;letter-spacing:.02em">Set via Budget Calculator → Publish</div>
            </div>
            <div class="field-group">
              <label class="field-label">Payment Deadline</label>
              <div class="date-input-wrap">
                <input class="field-input" type="text" id="fin-deadline" placeholder="Select deadline date" oninput="finPreviewUpdate()">
                <span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg></span>
              </div>
              <div style="font-size:.72rem;color:var(--sub);margin-top:.4rem;line-height:1.5">
                <strong>Note:</strong> This is when the final payment must be made. Usually 90 days prior to the start of the season.
              </div>
            </div>
          </div>

          <!-- Payment Mode Selection -->
          <div class="field-group" style="margin-top:.6rem">
            <label class="field-label">Payment Mode</label>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-top:.3rem">
              <div class="fin-toggle selected" id="fin-mode-full" onclick="finSetMode('full')" style="flex-direction:column;align-items:flex-start;gap:.3rem;padding:1rem 1.2rem">
                <div style="display:flex;align-items:center;gap:.5rem">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;flex-shrink:0"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                  <span style="font-family:'Oswald',sans-serif;font-size:.85rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase">Full Payment <span style="font-size:.6rem;background:#16a34a;color:#fff;padding:2px 7px;border-radius:10px;vertical-align:middle;font-weight:700;letter-spacing:.06em">RECOMMENDED</span></span>
                </div>
                <span style="font-size:.72rem;opacity:.75;font-weight:400;font-family:'Open Sans',sans-serif">Player pays total fee by deadline</span>
              </div>
              <div class="fin-toggle" id="fin-mode-monthly" onclick="finSetMode('monthly')" style="flex-direction:column;align-items:flex-start;gap:.3rem;padding:1rem 1.2rem">
                <div style="display:flex;align-items:center;gap:.5rem">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;flex-shrink:0"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>
                  <span style="font-family:'Oswald',sans-serif;font-size:.85rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase">Monthly Payments</span>
                </div>
                <span style="font-size:.72rem;opacity:.75;font-weight:400;font-family:'Open Sans',sans-serif">Auto-split fee across months</span>
              </div>
            </div>
          </div>

          <!-- Deposit Option (always shown) -->
          <div class="field-group" style="margin-top:.8rem">
            <label class="field-label">Deposit Option</label>
            <div style="display:flex;align-items:center;gap:.75rem;margin-top:.3rem">
              <div class="fin-toggle" id="fin-deposit-yes" onclick="finDepositToggle(true)" style="padding:.75rem 1.4rem">Yes</div>
              <div class="fin-toggle selected" id="fin-deposit-no" onclick="finDepositToggle(false)" style="padding:.75rem 1.4rem">No</div>
              <span style="font-size:.78rem;color:var(--sub)" id="fin-deposit-hint">Player pays full amount by deadline</span>
            </div>
          </div>

          <!-- Deposit Amount (shown when deposit yes) -->
          <div class="field-group" id="fin-deposit-amount-wrap" style="display:none;margin-top:.5rem">
            <label class="field-label">Deposit Amount <span style="font-weight:400;color:var(--sub)">($250 recommended)</span></label>
            <div style="position:relative;max-width:200px">
              <span style="position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--sub);font-size:.88rem;pointer-events:none">$</span>
              <input class="field-input" type="number" id="fin-deposit-amt" value="250" min="0" style="padding-left:26px" oninput="finPreviewUpdate()">
            </div>
          </div>

          <!-- Payment Plan Preview (shown when monthly selected) -->
          <div class="fin-plan-preview" id="fin-plan-preview" style="display:none;margin-top:1rem">
            <div class="fin-plan-title" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem">
              <span>Payment Plan Preview</span>
              <div style="display:flex;align-items:center;gap:.5rem">
                <span style="font-family:'Open Sans',sans-serif;font-size:.72rem;opacity:.7;font-weight:400">Simulate registration in:</span>
                <select id="fin-sim-month" onchange="finPreviewUpdate()" style="background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);border-radius:5px;color:#fff;font-size:.75rem;padding:4px 8px;cursor:pointer;outline:none">
                </select>
              </div>
            </div>
            <div id="fin-deposit-note" style="display:none;background:rgba(255,255,255,.08);border-radius:6px;padding:.6rem .9rem;margin-bottom:.75rem;font-size:.78rem;color:rgba(255,255,255,.8);line-height:1.5"></div>
            <div id="fin-plan-rows"><div class="fin-plan-empty">Fill in fee and deadline to see preview</div></div>
          </div>

          <button class="save-btn" id="save-fin-btn" onclick="saveFinancials()" style="margin-top:1.4rem">
            <span id="save-fin-txt">Save Financial Setup</span>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </button>
        </div>
      </div>

<!-- ACCOUNTS RECEIVABLE -->
      <div class="card">
        <div class="card-header">Accounts Receivable — Player Balances</div>
        <div class="card-body" style="padding:0">
          <div class="fin-summary-bar" style="padding:1.2rem 1.4rem 0" id="fin-summary-bar">
            <div class="fin-stat"><div class="fin-stat-label">Total Players</div><div class="fin-stat-value" id="fin-stat-players">0</div></div>
            <div class="fin-stat"><div class="fin-stat-label">Total Expected</div><div class="fin-stat-value" id="fin-stat-expected">$0</div></div>
            <div class="fin-stat"><div class="fin-stat-label">Total Collected</div><div class="fin-stat-value green" id="fin-stat-collected">$0</div></div>
            <div class="fin-stat"><div class="fin-stat-label">Outstanding</div><div class="fin-stat-value red" id="fin-stat-outstanding">$0</div></div>
          </div>
          <div style="overflow-x:auto;margin-top:1.2rem">
            <table class="ar-table">
              <thead>
                <tr>
                  <th>Player</th>
                  <th>Registered</th>
                  <th>Total Fee</th>
                  <th>Deposit</th>
                  <th>Paid</th>
                  <th>Balance</th>
                  <th>Deadline</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="ar-table-body">
                <tr><td colspan="9"><div class="no-ar-state">No player payment records yet.</div></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- PAYMENT DETAIL MODAL -->
      <div class="edit-overlay" id="payment-detail-overlay">
        <div class="edit-modal" style="max-width:600px">
          <div class="edit-modal-head">
            <h3 id="pd-modal-title">Payment Plan</h3>
            <button class="edit-modal-close" onclick="closePaymentDetail()">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
          </div>
          <div class="edit-modal-body" id="pd-modal-body" style="max-height:65vh;overflow-y:auto"></div>
          <div class="edit-modal-foot">
            <button class="edit-cancel-btn" onclick="closePaymentDetail()">Close</button>
          </div>
        </div>
      </div>

    </div>

    <!-- COST CALCULATOR PANEL -->
    <div class="dash-panel" id="panel-calculator">
      <div class="card" id="budget-form-wrap">
        <div class="card-header">Team Budget Calculator</div>
        <div class="card-body">
          <span class="calc-section-title">Budget Setup</span>
          <div class="calc-grid">
            <div class="calc-field"><label class="calc-label">Number of Paying Players</label><input class="calc-input" type="number" id="calc-players" placeholder="e.g. 14" min="0" oninput="calcUpdate()"></div>
            <div class="calc-field"><label class="calc-label"># of Seasons</label><input class="calc-input" type="number" id="calc-seasons" placeholder="e.g. 2" min="0" oninput="calcUpdate()"></div>
          </div>
          <hr class="calc-divider">
          <span class="calc-section-title">Tournaments / Events</span>
          <div class="calc-grid">
            <div class="calc-field"><label class="calc-label">Number of Events</label><input class="calc-input" type="number" id="calc-num-events" placeholder="e.g. 10" min="0" oninput="calcUpdate()"></div>
            <div class="calc-field"><label class="calc-label">Average Cost per Event</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-event-cost" placeholder="e.g. 500" min="0" oninput="calcUpdate()"></div></div>
          </div>
          <hr class="calc-divider">
          <span class="calc-section-title">Coaching Costs</span>
          <div class="calc-grid">
            <div class="calc-field"><label class="calc-label">Head Coach Pay</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-head-pay" placeholder="e.g. 3000" min="0" oninput="calcUpdate()"></div></div>
            <div class="calc-field"><label class="calc-label">Assistant Coach Pay</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-asst-pay" placeholder="e.g. 1500" min="0" oninput="calcUpdate()"></div></div>
          </div>
          <hr class="calc-divider">
          <span class="calc-section-title">Travel & Accommodations</span>
          <div class="calc-grid">
            <div class="calc-field"><label class="calc-label">Rentals</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-rentals" placeholder="e.g. 800" min="0" oninput="calcUpdate()"></div></div>
            <div class="calc-field"><label class="calc-label">Gas</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-gas" placeholder="e.g. 600" min="0" oninput="calcUpdate()"></div></div>
          </div>
          <div class="calc-grid" style="margin-top:.85rem">
            <div class="calc-field"><label class="calc-label">Nights of Hotels</label><input class="calc-input" type="number" id="calc-hotel-nights" placeholder="e.g. 5" min="0" oninput="calcUpdate()"></div>
            <div class="calc-field"><label class="calc-label">Average Hotel Cost per Night</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-hotel-avg" placeholder="e.g. 120" min="0" oninput="calcUpdate()"></div></div>
          </div>
          <hr class="calc-divider">
          <span class="calc-section-title">Equipment & Misc</span>
          <div class="calc-grid">
            <div class="calc-field"><label class="calc-label">No. of Coach Uniforms</label><input class="calc-input" type="number" id="calc-uniforms" placeholder="e.g. 3" min="0" oninput="calcUpdate()"></div>
            <div class="calc-field"><label class="calc-label">Uniform Cost Each</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-uniform-cost" placeholder="e.g. 80" min="0" oninput="calcUpdate()"></div></div>
          </div>
          <div class="calc-grid" style="margin-top:.85rem">
            <div class="calc-field"><label class="calc-label">Equipment (Balls, Fungo, etc.)</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-equipment" placeholder="e.g. 400" min="0" oninput="calcUpdate()"></div></div>
            <div class="calc-field"><label class="calc-label">Coach Liability Insurance</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-insurance" placeholder="e.g. 200" min="0" oninput="calcUpdate()"></div></div>
          </div>

          <hr class="calc-divider">
          <span class="calc-section-title">Other Expenses</span>
          <div class="calc-other-wrap" id="calc-other-wrap"></div>
          <button class="calc-add-other-btn" onclick="addOther()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add Other Expense
          </button>
          <div class="calc-totals-card">
            <div class="calc-totals-title">Budget Summary</div>
            <div class="calc-total-row"><span class="calc-total-label">Total Tournaments / Events</span><span class="calc-total-value" id="ct-tournaments">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Head Coach Pay</span><span class="calc-total-value" id="ct-head">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Assistant Coach Pay</span><span class="calc-total-value" id="ct-asst">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Rentals</span><span class="calc-total-value" id="ct-rentals">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Hotel Costs</span><span class="calc-total-value" id="ct-hotels">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Gas</span><span class="calc-total-value" id="ct-gas">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Coach Uniforms</span><span class="calc-total-value" id="ct-uniforms">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Equipment</span><span class="calc-total-value" id="ct-equipment">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Coach Liability Insurance</span><span class="calc-total-value" id="ct-insurance">$0.00</span></div>
            <div class="calc-total-row"><span class="calc-total-label">Ambassadors Baseball <span style="font-size:.75rem;opacity:.7;font-weight:400">($450 × Players)</span></span><span class="calc-total-value" id="ct-ambassadors">$0.00</span></div>
            <div id="ct-other-rows"></div>
            <div class="calc-total-row highlight"><span class="calc-total-label">Total Expenses</span><span class="calc-total-value" id="ct-total">$0.00</span></div>
            <div class="calc-total-row grand"><span class="calc-total-label">Player Fee (Total Expenses &divide; Paying Players)</span><span class="calc-total-value" id="ct-player-fee">$0.00</span></div>
          </div>
          <div style="display:flex;gap:.75rem;margin-top:1rem;flex-wrap:wrap">
            <button class="save-btn" id="save-budget-btn" onclick="saveBudgetAsDraft()" style="margin-top:0">
              <span id="save-budget-txt">Save as Draft</span>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:16px;height:16px"><polyline points="20 6 9 17 4 12"/></svg>
            </button>
            <button class="calc-reset-btn" onclick="calcReset()" style="margin-top:0">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
              Reset Calculator
            </button>
            <button class="budget-publish-btn" id="publish-budget-form-btn" onclick="publishBudgetFromForm()" style="margin-top:0">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px;height:14px"><path d="M5 12l5 5L20 7"/></svg>
              Publish
            </button>
            <button class="edit-cancel-btn" id="cancel-edit-budget-btn" onclick="cancelEditBudget()" style="display:none;margin-top:0">Cancel</button>
          </div>
        </div>
      </div>

      <!-- SAVED BUDGETS -->
      <div class="card" style="margin-top:1.4rem">
        <div class="card-header">Saved Budgets</div>
        <div class="card-body">
          <div id="saved-budgets-wrap">
            <div class="no-tryouts-dash" style="grid-column:1/-1">No budgets saved yet. Fill in the calculator and click Save Budget.</div>
          </div>
          <!-- INLINE BUDGET DETAIL -->
          <div id="budget-inline-detail" style="display:none;margin-top:1.4rem;border-top:2px solid var(--mid);padding-top:1.2rem"></div>
        </div>
      </div>

      <!-- BUDGET VIEW MODAL -->
      <div class="edit-overlay" id="budget-view-overlay">
        <div class="edit-modal" style="max-width:680px">
          <div class="edit-modal-head">
            <h3 id="bv-modal-title">Budget Details</h3>
            <button class="edit-modal-close" onclick="closeBudgetView()">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
          </div>
          <div class="edit-modal-body" style="max-height:70vh;overflow-y:auto" id="bv-modal-body">
          </div>
          <div class="edit-modal-foot">
            <button class="edit-cancel-btn" onclick="closeBudgetView()">Close</button>
          </div>
        </div>
      </div>

    </div>

  `;

  loadTryouts();
  loadDashRoster();
  loadDashSchedule();
  loadBudgetsLocal();

  // Init date pickers after DOM is rendered
  setTimeout(() => {
    const fpConfig = {
      dateFormat: 'F j, Y',
      allowInput: false,
      disableMobile: true,
    };
    flatpickr('#s-start-date', fpConfig);
    flatpickr('#s-end-date', fpConfig);
    flatpickr('#t-date', fpConfig);
    flatpickr('#fin-deadline', { dateFormat: 'F j, Y', allowInput: false, disableMobile: true, onChange: function() { finPopulateSimMonths(); finPreviewUpdate(); } });

    // Time range pickers
    const timeConfig = {
      enableTime: true,
      noCalendar: true,
      dateFormat: 'h:i K',
      time_24hr: false,
      allowInput: false,
      disableMobile: true,
      onClose: function() { combineTime(); }
    };
    flatpickr('#t-time-start', timeConfig);
    flatpickr('#t-time-end',   timeConfig);
  }, 100);
}

/* ── SAVE PROFILE ── */
async function saveProfile(){
  setLoading('save-profile-btn','save-profile-txt',true);
  try {
    const payload={
      firstName:   document.getElementById('p-firstname').value.trim(),
      lastName:    document.getElementById('p-lastname').value.trim(),
      emailPublic: document.getElementById('p-email-pub').value.trim(),
      phonePublic: document.getElementById('p-phone-pub').value.trim(),
      bio:         document.getElementById('p-bio').value.trim(),
    };
    const res=await fetch(`${API_BASE}/api/coach/update-profile`,{method:'PUT',headers:authH(),body:JSON.stringify(payload)});
    const data=await res.json();
    if(!res.ok) throw new Error(data.message||'Save failed');
    showMsg('msg-profile','Profile saved!','success');
    document.getElementById('dash-title').textContent=payload.firstName+' '+payload.lastName;
  } catch(err){ showMsg('msg-profile',err.message,'error'); }
  finally{ setLoading('save-profile-btn','save-profile-txt',false,'Save Profile'); }
}

/* ── SAVE TEAM DETAILS ── */
async function saveTeamDetails(){
  setLoading('save-td-btn','save-td-txt',true);
  try {
    const payload={
      teamName:    document.getElementById('td-teamname').value.trim(),
      state:       document.getElementById('td-state').value.trim().toUpperCase(),
      location:    document.getElementById('td-location')?.value.trim() || '',
      ageGroup:    document.getElementById('td-agegroup').value.trim(),
      teamDetails: document.getElementById('td-details').value.trim(),
      registerEnabled: document.getElementById('td-register-enabled').checked,
    };
    const res=await fetch(`${API_BASE}/api/coach/update-profile`,{method:'PUT',headers:authH(),body:JSON.stringify(payload)});
    const data=await res.json();
    if(!res.ok) throw new Error(data.message||'Save failed');
    showMsg('msg-teamdetails','Team details saved!','success');
    document.getElementById('dash-sub').textContent='Head Coach — '+payload.teamName;
  } catch(err){ showMsg('msg-teamdetails',err.message,'error'); }
  finally{ setLoading('save-td-btn','save-td-txt',false,'Save Team Details'); }
}

/* ── UPDATE REGISTER TOGGLE STATUS LABEL ── */
function updateRegisterStatus(){
  const chk=document.getElementById('td-register-enabled');
  const lbl=document.getElementById('td-register-status');
  if(!chk||!lbl) return;
  if(chk.checked){ lbl.textContent='Enabled'; lbl.className='toggle-status on'; }
  else            { lbl.textContent='Disabled'; lbl.className='toggle-status off'; }
}

/* ── SAVE ASSISTANTS ── */
async function saveAssistants(){
  setLoading('save-asst-btn','save-asst-txt',true);
  try {
    const payload={
      assistant1:{ name:document.getElementById('a1-name').value.trim(), role:document.getElementById('a1-role').value.trim()||'Assistant Coach', email:document.getElementById('a1-email').value.trim(), cell:document.getElementById('a1-cell').value.trim(), bio:document.getElementById('a1-bio').value.trim(), image:document.getElementById('a1-image-url').value||'' },
      assistant2:{ name:document.getElementById('a2-name').value.trim(), role:document.getElementById('a2-role').value.trim()||'Assistant Coach', email:document.getElementById('a2-email').value.trim(), cell:document.getElementById('a2-cell').value.trim(), bio:document.getElementById('a2-bio').value.trim(), image:document.getElementById('a2-image-url').value||'' }
    };
    const res=await fetch(`${API_BASE}/api/coach/update-assistants`,{method:'PUT',headers:authH(),body:JSON.stringify(payload)});
    const data=await res.json();
    if(!res.ok) throw new Error(data.message||'Save failed');
    showMsg('msg-assistants','Assistant coaches saved!','success');
  } catch(err){ showMsg('msg-assistants',err.message,'error'); }
  finally{ setLoading('save-asst-btn','save-asst-txt',false,'Save Assistants'); }
}

/* ── LOAD TRYOUTS ── */
async function loadTryouts(){
  const wrap=document.getElementById('tryouts-list-wrap'); if(!wrap) return;
  try {
    const res=await fetch(`${API_BASE}/api/coach/tryouts`,{headers:authH()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.message||'Failed');
    renderTryoutsList(data.tryouts||[]);
  } catch(err){ wrap.innerHTML='<p style="color:var(--red);font-size:.84rem">'+esc(err.message)+'</p>'; }
}

function renderTryoutsList(tryouts){
  tryouts=[...tryouts].sort((a,b)=>{const da=new Date(a.date),db=new Date(b.date);if(!isNaN(da)&&!isNaN(db))return da-db;return String(a.date).localeCompare(String(b.date));});
  _dashTryoutsData = tryouts;
  const wrap=document.getElementById('tryouts-list-wrap'); if(!wrap) return;
  if(!tryouts.length){ wrap.innerHTML='<div class="no-tryouts-dash">No tryouts scheduled yet. Create one above!</div>'; return; }
  wrap.innerHTML='<div class="tryouts-list">'+tryouts.map(t=>`
    <div class="tryout-item" id="tryout-${esc(t._id)}">
      <div>
        <div class="tryout-item-date">${esc(t.date)}<span class="tryout-item-fee">${esc(t.fee)}</span></div>
        <div class="tryout-item-meta">${esc(t.time)} &nbsp;&middot;&nbsp; ${esc(t.location)}</div>
      </div>
      <div style="display:flex;gap:.5rem;flex-shrink:0">
        <button class="roster-edit-btn" onclick="openEditTryout('${esc(t._id)}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit
        </button>
        <button class="delete-btn" onclick="deleteTryout('${esc(t._id)}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          Delete
        </button>
      </div>
    </div>`).join('')+'</div>';
}

/* ── TOGGLE ADD FEE AMOUNT ── */
function toggleAddFeeAmount() {
  const feeType = document.getElementById('t-fee-type').value;
  const container = document.getElementById('t-fee-container');
  
  if (feeType === 'fee') {
    // Replace with amount input
    container.innerHTML = `
      <div style="position:relative;display:flex;align-items:center;">
        <span style="position:absolute;left:14px;font-weight:600;color:var(--text);font-size:.88rem;pointer-events:none;">$</span>
        <input class="field-input" type="number" id="t-fee-amount" placeholder="Enter amount" style="padding-left:28px;">
      </div>
    `;
  } else {
    // Replace with dropdown
    container.innerHTML = `
      <select class="field-select" id="t-fee-type" onchange="toggleAddFeeAmount()">
        <option value="free">Free</option>
        <option value="fee">Fee</option>
      </select>
    `;
  }
}

/* ── COMBINE TIME ── */
function combineTime() {
  const start = document.getElementById('t-time-start').value.trim();
  const end   = document.getElementById('t-time-end').value.trim();
  const hidden = document.getElementById('t-time');
  if (start && end)   hidden.value = start + ' – ' + end;
  else if (start)     hidden.value = start;
  else                hidden.value = '';
}

/* ── ADD TRYOUT ── */
async function addTryout(){
  combineTime();
  const date=document.getElementById('t-date').value.trim();
  const time=document.getElementById('t-time').value.trim();
  const location=document.getElementById('t-location').value.trim();
  const city=document.getElementById('t-city').value.trim();
  const state=document.getElementById('t-state').value.trim().toUpperCase();
  
  if(!date||!time||!location){ showMsg('msg-tryout-add','Please fill in date, time and location.','error'); return; }
  
  // Get fee - check if it's the dropdown or the input
  let fee = 'Free';
  const feeDropdown = document.getElementById('t-fee-type');
  const feeAmountInput = document.getElementById('t-fee-amount');
  
  if (feeDropdown && feeDropdown.value === 'fee') {
    if (!feeAmountInput || !feeAmountInput.value.trim()) { 
      showMsg('msg-tryout-add','Please enter a fee amount.','error'); 
      return; 
    }
    fee = `$${feeAmountInput.value.trim()} Fee`;
  } else if (feeAmountInput) {
    // If amount input exists without dropdown, use its value
    const amount = feeAmountInput.value.trim();
    if (amount) fee = `$${amount} Fee`;
  }
  
  setLoading('add-tryout-btn','add-tryout-txt',true);
  try {
    const res=await fetch(`${API_BASE}/api/coach/tryouts`,{method:'POST',headers:authH(),body:JSON.stringify({date,time,location,fee,city,state})});
    const data=await res.json();
    if(!res.ok) throw new Error(data.message||'Failed');
    ['t-date','t-time','t-location','t-city','t-state'].forEach(id=>{ document.getElementById(id).value=''; });
    // Reset fee field
    document.getElementById('t-fee-container').innerHTML = `
      <select class="field-select" id="t-fee-type" onchange="toggleAddFeeAmount()">
        <option value="free">Free</option>
        <option value="fee">Fee</option>
      </select>
    `;
    document.getElementById('t-time-start')._flatpickr?.clear();
    document.getElementById('t-time-end')._flatpickr?.clear();
    showMsg('msg-tryout-add','Tryout added!','success');
    loadTryouts();
  } catch(err){ showMsg('msg-tryout-add',err.message,'error'); }
  finally{ setLoading('add-tryout-btn','add-tryout-txt',false,'Add Tryout'); }
}

/* ── EDIT TRYOUT ── */
let _editingTryoutId = null;
let _dashTryoutsData = [];

function openEditTryout(id) {
  const t = _dashTryoutsData.find(x => x._id === id);
  if (!t) return;
  _editingTryoutId = id;
  document.getElementById('et-id').value       = id;
  document.getElementById('et-location').value = t.location || '';
  
  // Parse fee - if it contains a number, set as fee; otherwise free
  const feeStr = t.fee || '';
  let feeType = 'free';
  let feeAmount = '';
  
  if (feeStr && feeStr !== 'Free' && feeStr.toLowerCase() !== 'free') {
    feeType = 'fee';
    const match = feeStr.match(/\$?(\d+(?:\.\d{2})?)/);
    if (match) feeAmount = match[1];
  }
  
  // Initialize fee container based on type
  const feeContainer = document.getElementById('et-fee-container');
  if (feeType === 'fee') {
    feeContainer.innerHTML = `
      <div style="position:relative;display:flex;align-items:center;">
        <span style="position:absolute;left:14px;font-weight:600;color:var(--text);font-size:.88rem;pointer-events:none;">$</span>
        <input class="field-input" type="number" id="et-fee-amount" placeholder="Enter amount" style="padding-left:28px;" value="${feeAmount}">
      </div>
    `;
  } else {
    feeContainer.innerHTML = `
      <select class="field-select" id="et-fee-type" onchange="toggleFeeAmount()">
        <option value="free">Free</option>
        <option value="fee">Fee</option>
      </select>
    `;
  }
  
  document.getElementById('et-city').value     = t.city     || '';
  document.getElementById('et-state').value    = t.state    || '';
  // Set date picker
  setTimeout(() => {
    const fpDate = document.getElementById('et-date')._flatpickr;
    if (fpDate) fpDate.setDate(t.date, false);
    else {
      const fp = flatpickr('#et-date', { dateFormat: 'F j, Y', allowInput: false, disableMobile: true });
      fp.setDate(t.date, false);
    }
    // Set time pickers
    const fpStart = document.getElementById('et-time-start')._flatpickr;
    const fpEnd   = document.getElementById('et-time-end')._flatpickr;
    const timeParts = (t.time || '').split(' – ');
    if (fpStart) fpStart.setDate(timeParts[0], false);
    else flatpickr('#et-time-start', { enableTime:true, noCalendar:true, dateFormat:'h:i K', time_24hr:false, allowInput:false, disableMobile:true, onClose: combineEditTime }).setDate(timeParts[0], false);
    if (fpEnd) fpEnd.setDate(timeParts[1]||'', false);
    else flatpickr('#et-time-end', { enableTime:true, noCalendar:true, dateFormat:'h:i K', time_24hr:false, allowInput:false, disableMobile:true, onClose: combineEditTime }).setDate(timeParts[1]||'', false);
    document.getElementById('et-time-start').value = timeParts[0] || '';
    document.getElementById('et-time-end').value   = timeParts[1] || '';
  }, 50);
  document.getElementById('tryout-edit-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function combineEditTime() {
  const start = document.getElementById('et-time-start').value.trim();
  const end   = document.getElementById('et-time-end').value.trim();
  const hidden = document.getElementById('et-time');
  if (start && end)  hidden.value = start + ' – ' + end;
  else if (start)    hidden.value = start;
  else               hidden.value = '';
}

function toggleFeeAmount() {
  const feeType = document.getElementById('et-fee-type').value;
  const container = document.getElementById('et-fee-container');
  
  if (feeType === 'fee') {
    // Replace with amount input
    container.innerHTML = `
      <div style="position:relative;display:flex;align-items:center;">
        <span style="position:absolute;left:14px;font-weight:600;color:var(--text);font-size:.88rem;pointer-events:none;">$</span>
        <input class="field-input" type="number" id="et-fee-amount" placeholder="Enter amount" style="padding-left:28px;">
      </div>
    `;
  } else {
    // Replace with dropdown
    container.innerHTML = `
      <select class="field-select" id="et-fee-type" onchange="toggleFeeAmount()">
        <option value="free">Free</option>
        <option value="fee">Fee</option>
      </select>
    `;
  }
}

function closeEditTryoutModal() {
  document.getElementById('tryout-edit-overlay').classList.remove('open');
  document.body.style.overflow = '';
  _editingTryoutId = null;
}

async function saveEditTryout() {
  if (!_editingTryoutId) return;
  combineEditTime();
  const date     = document.getElementById('et-date').value.trim();
  const time     = document.getElementById('et-time').value.trim();
  const location = document.getElementById('et-location').value.trim();
  const city     = document.getElementById('et-city').value.trim();
  const state    = document.getElementById('et-state').value.trim().toUpperCase();
  if (!date || !time || !location) { alert('Date, time and location are required.'); return; }
  
  // Get fee - check if it's the dropdown or the input
  let fee = 'Free';
  const feeDropdown = document.getElementById('et-fee-type');
  const feeAmountInput = document.getElementById('et-fee-amount');
  
  if (feeDropdown && feeDropdown.value === 'fee') {
    if (!feeAmountInput || !feeAmountInput.value.trim()) { 
      alert('Please enter a fee amount.'); 
      return; 
    }
    fee = `$${feeAmountInput.value.trim()} Fee`;
  } else if (feeAmountInput) {
    // If amount input exists without dropdown, use its value
    const amount = feeAmountInput.value.trim();
    if (amount) fee = `$${amount} Fee`;
  }
  
  const btn = document.getElementById('et-save-btn');
  btn.textContent = 'Saving…'; btn.disabled = true;
  try {
    const res  = await fetch(`${API_BASE}/api/coach/tryouts/${_editingTryoutId}`, {
      method: 'PUT', headers: authH(),
      body: JSON.stringify({ date, time, location, fee, city, state })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    closeEditTryoutModal();
    await loadTryouts();
  } catch(err) { alert('Error: ' + err.message); }
  finally { btn.textContent = 'Save Changes'; btn.disabled = false; }
}

/* ── DELETE TRYOUT ── */
async function deleteTryout(id){
  if(!confirm('Delete this tryout?')) return;
  try {
    const res=await fetch(`${API_BASE}/api/coach/tryouts/${id}`,{method:'DELETE',headers:authH()});
    const data=await res.json();
    if(!res.ok) throw new Error(data.message||'Delete failed');
    document.getElementById('tryout-'+id)?.remove();
    const list=document.querySelector('.tryouts-list');
    if(list&&!list.children.length) document.getElementById('tryouts-list-wrap').innerHTML='<div class="no-tryouts-dash">No tryouts scheduled yet. Create one above!</div>';
    showMsg('msg-tryout-list','Tryout deleted.','success');
  } catch(err){ showMsg('msg-tryout-list',err.message,'error'); }
}

/* ── PHOTO UPLOAD — HEAD COACH ── */
async function handlePhotoUpload(input, previewId, statusId, imgId) {
  const file = input.files[0];
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) { alert('Image must be under 5MB'); return; }
  const status = document.getElementById(statusId);
  status.textContent = 'Uploading…';
  const reader = new FileReader();
  reader.onload = async function(e) {
    const base64 = e.target.result.split(',')[1];
    try {
      const res = await fetch(`${API_BASE}/api/coach/upload-image`, {
        method: 'POST', headers: authH(),
        body: JSON.stringify({ base64, fileName: file.name, mimeType: file.type, saveToProfile: true, slot: 'head' })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      // Update preview
      const preview = document.getElementById(previewId);
      preview.innerHTML = '<img id="'+imgId+'" src="'+data.imageUrl+'" style="width:100%;height:100%;object-fit:cover;border-radius:50%">';
      // Show Edit/Delete buttons
      setPhotoBtns('p-photo-btn-row', true, 'p-photo-input', 'head', 'p-photo-preview', 'p-photo-status', null);
      status.textContent = 'Photo saved!';
      setTimeout(()=>{ status.textContent=''; }, 2500);
    } catch(err) { status.textContent = 'Error: ' + err.message; }
  };
  reader.readAsDataURL(file);
}
/* ── PHOTO DELETE ── */
function setPhotoBtns(btnRowId, hasPhoto, inputId, slot, previewId, statusId, hiddenId) {
  const row = document.getElementById(btnRowId);
  if (!row) return;
  // Replace file input with a fresh clone so onchange always fires reliably
  const fileInput = document.getElementById(inputId);
  if (fileInput) {
    const clone = fileInput.cloneNode(true);
    fileInput.parentNode.replaceChild(clone, fileInput);
  }
  if (hasPhoto) {
    row.innerHTML = `
      <button class="photo-edit-btn edit" onclick="document.getElementById('${inputId}').value='';document.getElementById('${inputId}').click()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Edit Photo
      </button>
      <button class="photo-edit-btn delete" onclick="deletePhoto('${slot}','${previewId}','${statusId}','${btnRowId}'${hiddenId ? `,'${hiddenId}'` : ''})">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
        Delete
      </button>`;
  } else {
    row.innerHTML = `
      <button class="photo-edit-btn edit" onclick="document.getElementById('${inputId}').value='';document.getElementById('${inputId}').click()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        Upload Photo
      </button>`;
  }
}

async function deletePhoto(slot, previewId, statusId, btnRowId, hiddenId) {
  const status = document.getElementById(statusId);
  status.textContent = 'Deleting…';
  try {
    const res = await fetch(`${API_BASE}/api/coach/delete-image`, {
      method: 'DELETE', headers: authH(),
      body: JSON.stringify({ slot })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message);
    // Clear preview
    const preview = document.getElementById(previewId);
    preview.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>';
    // Clear hidden input
    if (hiddenId) { const h = document.getElementById(hiddenId); if (h) h.value = ''; }
    // Show upload button
    const inputId = slot === 'head' ? 'p-photo-input' : slot === 'asst1' ? 'a1-photo-input' : 'a2-photo-input';
    setPhotoBtns(btnRowId, false, inputId, slot, previewId, statusId, hiddenId);
    if (slot !== 'head') await saveAssistantsSilent();
    status.textContent = 'Photo deleted.';
    setTimeout(()=>{ status.textContent=''; }, 2500);
  } catch(err) { status.textContent = 'Error: ' + err.message; }
}


/* ── PHOTO UPLOAD — ASSISTANT ── */
async function handleAsstPhotoUpload(input, previewId, statusId, imgId, hiddenId, slot, btnRowId) {
  const file = input.files[0];
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) { alert('Image must be under 5MB'); return; }
  const status = document.getElementById(statusId);
  status.textContent = 'Uploading…';
  const reader = new FileReader();
  reader.onload = async function(e) {
    const base64 = e.target.result.split(',')[1];
    try {
      const res = await fetch(`${API_BASE}/api/coach/upload-image`, {
        method: 'POST', headers: authH(),
        body: JSON.stringify({ base64, fileName: file.name, mimeType: file.type, saveToProfile: false, slot })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message);
      // Update preview
      document.getElementById(previewId).innerHTML = '<img id="'+imgId+'" src="'+data.imageUrl+'" style="width:100%;height:100%;object-fit:cover;border-radius:50%">';
      // Store URL and show Edit/Delete buttons
      const hiddenEl = document.getElementById(hiddenId);
      if (hiddenEl) hiddenEl.value = data.imageUrl;
      setPhotoBtns(btnRowId, true, input.id, slot, previewId, statusId, hiddenId);
      await saveAssistantsSilent();
      status.textContent = 'Photo saved!';
      setTimeout(()=>{ status.textContent=''; }, 2500);
    } catch(err) { status.textContent = 'Upload failed: ' + err.message; }
  };
  reader.readAsDataURL(file);
}

// Save assistants without showing success/error messages — used after image upload
async function saveAssistantsSilent() {
  try {
    const payload = {
      assistant1:{ name:document.getElementById('a1-name')?.value.trim()||'', role:document.getElementById('a1-role')?.value.trim()||'Assistant Coach', email:document.getElementById('a1-email')?.value.trim()||'', cell:document.getElementById('a1-cell')?.value.trim()||'', bio:document.getElementById('a1-bio')?.value.trim()||'', image:document.getElementById('a1-image-url')?.value||'' },
      assistant2:{ name:document.getElementById('a2-name')?.value.trim()||'', role:document.getElementById('a2-role')?.value.trim()||'Assistant Coach', email:document.getElementById('a2-email')?.value.trim()||'', cell:document.getElementById('a2-cell')?.value.trim()||'', bio:document.getElementById('a2-bio')?.value.trim()||'', image:document.getElementById('a2-image-url')?.value||'' }
    };
    await fetch(`${API_BASE}/api/coach/update-assistants`, { method:'PUT', headers:authH(), body:JSON.stringify(payload) });
  } catch(e) { /* silent */ }
}

/* ── DASHBOARD ROSTER ── */
let dashRosterData = [];
let editingPlayerId = null;

async function loadDashRoster() {
  const coachId = localStorage.getItem('coach_id');
  if (!coachId) return;
  try {
    const res = await fetch(`${API_BASE}/api/teams/${coachId}/roster`);
    const data = await res.json();
    dashRosterData = data.players || [];
    renderDashRoster(dashRosterData);
  } catch(err) {
    const tbody = document.getElementById('dash-roster-body');
    if (tbody) tbody.innerHTML = '<tr><td colspan="10"><div class="empty-roster-dash">Failed to load roster.</div></td></tr>';
  }
}

function renderDashRoster(players) {
  const tbody = document.getElementById('dash-roster-body');
  if (!tbody) return;
  if (!players.length) {
    tbody.innerHTML = '<tr><td colspan="10"><div class="empty-roster-dash">No players have registered yet.</div></td></tr>';
    return;
  }
  tbody.innerHTML = players.map(p => `
    <tr id="prow-${esc(p._id)}">
      <td>${esc(p.name)}</td>
      <td>${esc(p.jersey||'—')}</td>
      <td>${esc(p.gradYear||'—')}</td>
      <td>${esc(p.position||'—')}</td>
      <td>${esc(p.hw||'—')}</td>
      <td>${esc(p.city||'—')}</td>
      <td>${esc(p.state||'—')}</td>
      <td>${p.email ? `<a href="mailto:${esc(p.email)}" style="color:var(--navy);text-decoration:none;font-weight:500">${esc(p.email)}</a>` : '—'}</td>
      <td>${p.cell ? `<a href="tel:+1${p.cell.replace(/\D/g,'')}" style="color:var(--navy);text-decoration:none;font-weight:500">${esc(p.cell)}</a>` : '—'}</td>
      <td style="white-space:nowrap">
        <button class="roster-edit-btn" onclick="openEditPlayer('${esc(p._id)}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit
        </button>
        <button class="roster-del-btn" onclick="deletePlayer('${esc(p._id)}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          Delete
        </button>
      </td>
    </tr>`).join('');
}

function openEditPlayer(id) {
  const p = dashRosterData.find(x => x._id === id);
  if (!p) return;
  editingPlayerId = id;
  document.getElementById('ep-name').value     = p.name     || '';
  document.getElementById('ep-jersey').value   = p.jersey   || '';
  document.getElementById('ep-gradyear').value = p.gradYear || '';
  document.getElementById('ep-hw').value       = p.hw       || '';
  document.getElementById('ep-city').value     = p.city     || '';
  document.getElementById('ep-state').value    = p.state    || '';
  document.getElementById('ep-position').value = p.position || '';
  document.getElementById('ep-email').value    = p.email    || '';
  document.getElementById('ep-cell').value     = p.cell     || '';
  document.getElementById('edit-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeEditModal() {
  document.getElementById('edit-overlay').classList.remove('open');
  document.body.style.overflow = '';
  editingPlayerId = null;
}

async function saveEditPlayer() {
  if (!editingPlayerId) return;
  const coachId = localStorage.getItem('coach_id');
  const payload = {
    name:     document.getElementById('ep-name').value.trim(),
    jersey:   document.getElementById('ep-jersey').value.trim(),
    gradYear: document.getElementById('ep-gradyear').value.trim(),
    position: document.getElementById('ep-position').value,
    hw:       document.getElementById('ep-hw').value.trim(),
    city:     document.getElementById('ep-city').value.trim(),
    state:    document.getElementById('ep-state').value.trim(),
    email:    document.getElementById('ep-email').value.trim(),
    cell:     document.getElementById('ep-cell').value.trim(),
  };
  if (!payload.name) { alert('Player name is required'); return; }
  const btn = document.getElementById('ep-save-btn');
  btn.textContent = 'Saving…'; btn.disabled = true;
  try {
    const res = await fetch(`${API_BASE}/api/teams/${coachId}/roster/${editingPlayerId}`, {
      method: 'PUT', headers: authH(), body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    closeEditModal();
    await loadDashRoster();
  } catch(err) { alert('Error: ' + err.message); }
  finally { btn.textContent = 'Save Changes'; btn.disabled = false; }
}

async function deletePlayer(id) {
  if (!confirm('Remove this player from the roster?')) return;
  const coachId = localStorage.getItem('coach_id');
  try {
    const res = await fetch(`${API_BASE}/api/teams/${coachId}/roster/${id}`, {
      method: 'DELETE', headers: authH()
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    dashRosterData = dashRosterData.filter(p => p._id !== id);
    renderDashRoster(dashRosterData);
  } catch(err) { alert('Error: ' + err.message); }
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeEditModal(); closeEditGameModal(); closeEditTryoutModal(); closeBudgetView(); closePaymentDetail(); } });

/* Prevent arrow keys from changing number input values */
document.addEventListener('keydown', (e) => {
  if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && e.target.type === 'number') {
    e.preventDefault();
  }
});


/* ── DASHBOARD SCHEDULE ── */
let dashSchedData = [];

async function loadDashSchedule() {
  try {
    const res  = await fetch(`${API_BASE}/api/coach/schedule`, { headers: authH() });
    const data = await res.json();
    dashSchedData = data.schedule || [];
    // Sort by startDate (earliest first)
    dashSchedData.sort((a, b) => {
      const dateA = new Date(a.startDate);
      const dateB = new Date(b.startDate);
      return dateA - dateB;
    });
    renderDashSchedule(dashSchedData);
  } catch(err) {
    const tbody = document.getElementById('dash-sched-body');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5"><div class="no-schedule-dash">Failed to load schedule.</div></td></tr>';
  }
}

function renderDashSchedule(games) {
  const tbody = document.getElementById('dash-sched-body');
  if (!tbody) return;
  if (!games.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="no-schedule-dash">No games added yet. Add one above!</div></td></tr>';
    return;
  }
  tbody.innerHTML = games.map(g => {
    // Display date range if we have both startDate and endDate
    let dateDisplay = '';
    if (g.startDate && g.endDate) {
      dateDisplay = g.startDate === g.endDate 
        ? esc(g.startDate) 
        : `${esc(g.startDate)} - ${esc(g.endDate)}`;
    } else if (g.date) {
      // Fallback to old date field if new fields aren't available
      dateDisplay = esc(g.date);
    } else {
      dateDisplay = '—';
    }
    
    return `
    <tr id="grow-${esc(g._id)}">
      <td>${dateDisplay}</td>
      <td>${esc(g.event)}</td>
      <td>${esc(g.city||'—')}</td>
      <td>${esc(g.state||'—')}</td>
      <td style="white-space:nowrap">
        <button class="roster-edit-btn" onclick="openEditGame('${esc(g._id)}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit
        </button>
        <button class="roster-del-btn" onclick="deleteGame('${esc(g._id)}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          Delete
        </button>
      </td>
    </tr>`;
  }).join('');
}


async function openEditGame(id) {
  const g = dashSchedData.find(x => x._id === id);
  if (!g) return;
  document.getElementById('eg-id').value        = id;
  document.getElementById('eg-event').value     = g.event || '';
  document.getElementById('eg-city').value      = g.city  || '';
  document.getElementById('eg-state').value     = g.state || '';
  document.getElementById('sched-edit-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
  // Init date pickers after modal is visible, then set values
  setTimeout(() => {
    const fpStart = flatpickr('#eg-start-date', { dateFormat: 'F j, Y', allowInput: false, disableMobile: true });
    const fpEnd = flatpickr('#eg-end-date', { dateFormat: 'F j, Y', allowInput: false, disableMobile: true });
    if (g.startDate) fpStart.setDate(g.startDate, false);
    if (g.endDate) fpEnd.setDate(g.endDate, false);
  }, 50);
}

function closeEditGameModal() {
  document.getElementById('sched-edit-overlay').classList.remove('open');
  document.body.style.overflow = '';
}

async function saveEditGame() {
  const id        = document.getElementById('eg-id').value;
  const startDate = document.getElementById('eg-start-date').value.trim();
  const endDate   = document.getElementById('eg-end-date').value.trim();
  const event     = document.getElementById('eg-event').value.trim();
  const city      = document.getElementById('eg-city').value.trim();
  const state     = document.getElementById('eg-state').value.trim().toUpperCase();
  if (!startDate || !endDate || !event) { alert('Start date, end date, and event name are required.'); return; }
  const btn = document.getElementById('eg-save-btn');
  btn.textContent = 'Saving…'; btn.disabled = true;
  try {
    const res  = await fetch(`${API_BASE}/api/coach/schedule/${id}`, {
      method: 'PUT', headers: authH(),
      body: JSON.stringify({ startDate, endDate, event, city, state })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    closeEditGameModal();
    await loadDashSchedule();
  } catch(err) { alert('Error: ' + err.message); }
  finally { btn.textContent = 'Save Changes'; btn.disabled = false; }
}


let _allTryoutRegs = [];
let _allDashTryouts = [];

async function loadTryoutRegs() {
  const cardsWrap = document.getElementById('tryreg-cards-wrap');
  const tableWrap = document.getElementById('tryreg-table-wrap');
  cardsWrap.innerHTML = '<div class="no-schedule-dash">Loading…</div>';
  tableWrap.style.display = 'none';
  try {
    // Load tryouts and registrations in parallel
    const [tryoutsRes, regsRes] = await Promise.all([
      fetch(`${API_BASE}/api/coach/tryouts`, { headers: authH() }),
      fetch(`${API_BASE}/api/coach/tryout-registrations`, { headers: authH() })
    ]);
    const tryoutsData = await tryoutsRes.json();
    const regsData    = await regsRes.json();
    _allDashTryouts   = tryoutsData.tryouts  || [];
    _allTryoutRegs    = regsData.registrations || [];

    if (!_allDashTryouts.length) {
      cardsWrap.innerHTML = '<div class="no-schedule-dash">No tryouts created yet. Add one in the Tryouts tab.</div>';
      return;
    }

    cardsWrap.innerHTML = _allDashTryouts.map(t => {
      const count = _allTryoutRegs.filter(r => r.tryout_date === t.date).length;
      return `
        <div class="tryreg-tryout-card" onclick="showTryregForTryout('${esc(t.date)}', '${esc(t.location||'')}')">
          <div class="tryreg-tryout-card-top">
            <span class="tryout-fee-badge">${esc(t.fee||'Free')}</span>
            <span class="tryreg-count-badge">${count} registered</span>
          </div>
          <div class="tryreg-tryout-date">${esc(t.date)}</div>
          <div class="tryreg-tryout-meta">${esc(t.time||'')}</div>
          <div class="tryreg-tryout-meta" style="display:flex;align-items:center;gap:5px;margin-top:4px">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" style="width:13px;height:13px;flex-shrink:0"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7z"/><circle cx="12" cy="9" r="2.5"/></svg>
            ${esc(t.location||'—')}
          </div>
          <div class="tryreg-view-regs-btn">View Registrations</div>
        </div>`;
    }).join('');
  } catch(err) {
    cardsWrap.innerHTML = '<div class="no-schedule-dash">Failed to load tryouts.</div>';
  }
}

function showTryregForTryout(date, location) {
  // Highlight selected card
  document.querySelectorAll('.tryreg-tryout-card').forEach(c => c.classList.remove('selected'));
  event.currentTarget.classList.add('selected');

  const tableWrap = document.getElementById('tryreg-table-wrap');
  const tbody     = document.getElementById('tryreg-body');
  const heading   = document.getElementById('tryreg-table-heading');

  const regs = _allTryoutRegs.filter(r => r.tryout_date === date);
  heading.textContent = `Registrations — ${date}${location ? ' @ ' + location : ''} (${regs.length})`;
  tableWrap.style.display = 'block';

  if (!regs.length) {
    tbody.innerHTML = '<tr><td colspan="10"><div class="no-schedule-dash">No registrations for this tryout yet.</div></td></tr>';
    return;
  }
  tbody.innerHTML = regs.map(r => {
    const isPaid    = !r.status || r.status === 'confirmed';
    const badge     = isPaid
      ? `<span style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0;border-radius:20px;padding:3px 10px;font-size:.72rem;font-weight:700;font-family:'Oswald',sans-serif;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap">✅ Confirmed</span>`
      : `<span style="background:#fff7ed;color:#9a3412;border:1px solid #fed7aa;border-radius:20px;padding:3px 10px;font-size:.72rem;font-weight:700;font-family:'Oswald',sans-serif;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap">⏳ Pending</span>`;
    return `
    <tr>
      <td style="font-weight:600;color:var(--navy)">${esc(r.player_name||'—')}</td>
      <td>${esc(r.name||'—')}</td>
      <td>${esc(r.email||'—')}</td>
      <td>${esc(r.cell||'—')}</td>
      <td>${esc([r.pos1,r.pos2].filter(Boolean).join(', ')||'—')}</td>
      <td>${esc(r.age||'—')}</td>
      <td>${esc(r.hw||'—')}</td>
      <td>${esc(r.completed_by||'—')}</td>
      <td>${esc([r.address, r.city, r.state, r.zip].filter(Boolean).join(', ')||'—')}</td>
      <td>${badge}</td>
    </tr>`;
  }).join('');

  tableWrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function addGame() {
  const startDate = document.getElementById('s-start-date').value.trim();
  const endDate   = document.getElementById('s-end-date').value.trim();
  const event     = document.getElementById('s-event').value.trim();
  const city      = document.getElementById('s-city').value.trim();
  const state     = document.getElementById('s-state').value.trim().toUpperCase();
  if (!startDate || !endDate || !event) { showMsg('msg-sched-add', 'Start date, end date, and event name are required.', 'error'); return; }
  setLoading('add-game-btn', 'add-game-txt', true);
  try {
    const res  = await fetch(`${API_BASE}/api/coach/schedule`, {
      method: 'POST', headers: authH(),
      body: JSON.stringify({ startDate, endDate, event, city, state })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    ['s-start-date','s-end-date','s-event','s-city','s-state'].forEach(id => { document.getElementById(id).value = ''; });
    showMsg('msg-sched-add', 'Game added!', 'success');
    await loadDashSchedule();
  } catch(err) { showMsg('msg-sched-add', err.message, 'error'); }
  finally { setLoading('add-game-btn', 'add-game-txt', false, 'Add to Schedule'); }
}

async function deleteGame(id) {
  if (!confirm('Remove this game from the schedule?')) return;
  try {
    const res  = await fetch(`${API_BASE}/api/coach/schedule/${id}`, {
      method: 'DELETE', headers: authH()
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    dashSchedData = dashSchedData.filter(g => g._id !== id);
    renderDashSchedule(dashSchedData);
  } catch(err) { alert('Error: ' + err.message); }
}

/* ══════════════════════════════════════
   BUDGET CALCULATOR
══════════════════════════════════════ */
let _budgets = [];
let _editingBudgetIdx = null;

function fmt(n){ return '$' + (isNaN(n) ? 0 : Number(n)).toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}); }
function num(id){ return parseFloat(document.getElementById(id)?.value) || 0; }
function str(id){ return document.getElementById(id)?.value?.trim() || ''; }

function calcBudget() {
  const events  = num('b-events-num') * num('b-events-cost');
  const hotel   = num('b-hotel-nights') * num('b-hotel-cost');
  const head    = num('b-head-pay');
  const asst    = num('b-asst-pay');
  const rentals = num('b-rentals');
  const gas     = num('b-gas');
  const uni     = num('b-uniforms');
  const equip   = num('b-equipment');
  const ins     = num('b-insurance');
  const amb     = num('b-ambassadors');
  const oth1    = num('b-other1-amt');
  const oth2    = num('b-other2-amt');
  const oth3    = num('b-other3-amt');
  const total   = events + head + asst + rentals + hotel + gas + uni + equip + ins + amb + oth1 + oth2 + oth3;
  const players = num('b-players') || 0;

  // Auto-fill totals
  document.getElementById('b-events-total').value = events || '';
  document.getElementById('b-hotel-total').value  = hotel  || '';

  // Update summary
  document.getElementById('bt-events').textContent     = fmt(events);
  document.getElementById('bt-head').textContent       = fmt(head);
  document.getElementById('bt-asst').textContent       = fmt(asst);
  document.getElementById('bt-rentals').textContent    = fmt(rentals);
  document.getElementById('bt-hotel').textContent      = fmt(hotel);
  document.getElementById('bt-gas').textContent        = fmt(gas);
  document.getElementById('bt-uniforms').textContent   = fmt(uni);
  document.getElementById('bt-equipment').textContent  = fmt(equip);
  document.getElementById('bt-insurance').textContent  = fmt(ins);
  document.getElementById('bt-ambassadors').textContent= fmt(amb);

  const o1lbl = str('b-other1-label') || 'Other 1';
  const o2lbl = str('b-other2-label') || 'Other 2';
  const o3lbl = str('b-other3-label') || 'Other 3';
  document.getElementById('bt-other1-lbl').textContent = o1lbl;
  document.getElementById('bt-other2-lbl').textContent = o2lbl;
  document.getElementById('bt-other3-lbl').textContent = o3lbl;
  document.getElementById('bt-other1').textContent     = fmt(oth1);
  document.getElementById('bt-other2').textContent     = fmt(oth2);
  document.getElementById('bt-other3').textContent     = fmt(oth3);
  document.getElementById('bt-total').textContent      = fmt(total);

  const fee = players > 0 ? total / players : 0;
  document.getElementById('bt-player-fee').textContent = fmt(fee) + ' / player';
}

function getBudgetData() {
  const events = num('b-events-num') * num('b-events-cost');
  const hotel  = num('b-hotel-nights') * num('b-hotel-cost');
  const head   = num('b-head-pay');
  const asst   = num('b-asst-pay');
  const rentals= num('b-rentals');
  const gas    = num('b-gas');
  const uni    = num('b-uniforms');
  const equip  = num('b-equipment');
  const ins    = num('b-insurance');
  const amb    = num('b-ambassadors');
  const oth1   = num('b-other1-amt');
  const oth2   = num('b-other2-amt');
  const oth3   = num('b-other3-amt');
  const total  = events + head + asst + rentals + hotel + gas + uni + equip + ins + amb + oth1 + oth2 + oth3;
  const players= num('b-players');
  return {
    name: str('b-name') || 'Untitled Budget',
    players, seasons: num('b-seasons'),
    eventsNum: num('b-events-num'), eventsCost: num('b-events-cost'), eventsTotal: events,
    headPay: head, asstPay: asst, rentals, gas,
    hotelNights: num('b-hotel-nights'), hotelCost: num('b-hotel-cost'), hotelTotal: hotel,
    uniforms: uni, equipment: equip, insurance: ins, ambassadors: amb,
    other1Label: str('b-other1-label'), other1Amt: oth1,
    other2Label: str('b-other2-label'), other2Amt: oth2,
    other3Label: str('b-other3-label'), other3Amt: oth3,
    totalExpenses: total,
    playerFee: players > 0 ? total / players : 0,
    createdAt: new Date().toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'})
  };
}

function saveBudget() {
  const data = getBudgetData();
  if (!data.name) { showMsg('msg-budget','Please enter a budget name.','error'); return; }
  if (_editingBudgetIdx !== null) {
    _budgets[_editingBudgetIdx] = data;
    _editingBudgetIdx = null;
    document.getElementById('add-budget-txt').textContent = 'Save Budget';
  } else {
    _budgets.unshift(data);
  }
  saveBudgetsLocal();
  renderBudgetList();
  clearBudgetForm();
  showMsg('msg-budget', 'Budget saved!', 'success');
}

function saveBudgetsLocal() {
  try { localStorage.setItem('coach_budgets_' + localStorage.getItem('coach_id'), JSON.stringify(_budgets)); } catch(e){}
}

function loadBudgetsLocal() {
  try {
    const raw = localStorage.getItem('coach_budgets_' + localStorage.getItem('coach_id'));
    _budgets = raw ? JSON.parse(raw) : [];
  } catch(e) { _budgets = []; }
  renderBudgetList();
}

function clearBudgetForm() {
  ['b-name','b-players','b-seasons','b-events-num','b-events-cost','b-events-total',
   'b-head-pay','b-asst-pay','b-rentals','b-gas','b-hotel-nights','b-hotel-cost','b-hotel-total',
   'b-uniforms','b-equipment','b-insurance','b-ambassadors','b-other1-label','b-other1-amt',
   'b-other2-label','b-other2-amt','b-other3-label','b-other3-amt'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  calcBudget();
}

function renderBudgetList() {
  const wrap = document.getElementById('budget-list-wrap');
  if (!wrap) return;
  if (!_budgets.length) {
    wrap.innerHTML = '<div class="no-tryouts-dash">No budgets saved yet. Create one above!</div>';
    return;
  }
  wrap.innerHTML = _budgets.map((b, i) => `
    <div class="budget-list-item">
      <div class="budget-list-item-header">
        <div>
          <div class="budget-list-name">${esc(b.name)}</div>
          <div class="budget-list-meta">${esc(b.createdAt)} &nbsp;·&nbsp; ${b.players || 0} players &nbsp;·&nbsp; ${b.seasons || 1} season(s)</div>
        </div>
        <div style="text-align:right">
          <div class="budget-list-fee">${fmt(b.totalExpenses)}</div>
          <div style="font-size:.72rem;color:var(--sub);margin-top:2px">Player Fee: ${fmt(b.playerFee)}</div>
        </div>
      </div>
      <div class="budget-list-actions" style="margin-top:.75rem">
        <button class="roster-edit-btn" onclick="viewBudget(${i})">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px;height:12px"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          View
        </button>
        <button class="roster-edit-btn" onclick="editBudget(${i})">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px;height:12px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit
        </button>
        <button class="roster-del-btn" onclick="deleteBudget(${i})">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px;height:12px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          Delete
        </button>
      </div>
    </div>`).join('');
}

function closeBudgetView() {
  document.getElementById('budget-view-overlay')?.classList.remove('open');
  document.body.style.overflow = '';
}

function editBudget(i) {
  const b = _budgets[i];
  _editingBudgetIdx = i;
  document.getElementById('b-name').value          = b.name || '';
  document.getElementById('b-players').value       = b.players || '';
  document.getElementById('b-seasons').value       = b.seasons || '';
  document.getElementById('b-events-num').value    = b.eventsNum || '';
  document.getElementById('b-events-cost').value   = b.eventsCost || '';
  document.getElementById('b-head-pay').value      = b.headPay || '';
  document.getElementById('b-asst-pay').value      = b.asstPay || '';
  document.getElementById('b-rentals').value       = b.rentals || '';
  document.getElementById('b-gas').value           = b.gas || '';
  document.getElementById('b-hotel-nights').value  = b.hotelNights || '';
  document.getElementById('b-hotel-cost').value    = b.hotelCost || '';
  document.getElementById('b-uniforms').value      = b.uniforms || '';
  document.getElementById('b-equipment').value     = b.equipment || '';
  document.getElementById('b-insurance').value     = b.insurance || '';
  document.getElementById('b-ambassadors').value   = b.ambassadors || 450;
  document.getElementById('b-other1-label').value  = b.other1Label || '';
  document.getElementById('b-other1-amt').value    = b.other1Amt || '';
  document.getElementById('b-other2-label').value  = b.other2Label || '';
  document.getElementById('b-other2-amt').value    = b.other2Amt || '';
  document.getElementById('b-other3-label').value  = b.other3Label || '';
  document.getElementById('b-other3-amt').value    = b.other3Amt || '';
  calcBudget();
  document.getElementById('add-budget-txt').textContent = 'Update Budget';
}

function deleteBudget(i) {
  if (!confirm('Delete this budget?')) return;
  _budgets.splice(i, 1);
  saveBudgetsLocal();
  renderBudgetList();
}

/* ── TEAM FINANCIALS ── */
let _finSetup = null;
let _playerPayments = [];
let _finFullPay = true;
let _finDepositEnabled = false;
let _finMonthly = false;

function finSetMode(mode) {
  _finMonthly  = (mode === 'monthly');
  _finFullPay  = (mode === 'full');
  document.getElementById('fin-mode-full').classList.toggle('selected', mode === 'full');
  document.getElementById('fin-mode-monthly').classList.toggle('selected', mode === 'monthly');
  const preview = document.getElementById('fin-plan-preview');
  if (preview) preview.style.display = _finMonthly ? 'block' : 'none';
  if (_finMonthly) {
    finPopulateSimMonths();
    finPreviewUpdate();
  }
}

function finDepositToggle(enabled) {
  _finDepositEnabled = enabled;
  document.getElementById('fin-deposit-yes').classList.toggle('selected', enabled);
  document.getElementById('fin-deposit-no').classList.toggle('selected', !enabled);
  document.getElementById('fin-deposit-amount-wrap').style.display = enabled ? 'block' : 'none';
  const hint = document.getElementById('fin-deposit-hint');
  if (hint) hint.textContent = enabled
    ? 'Player pays deposit now, balance due by deadline'
    : 'Player pays full amount by deadline';
  finPreviewUpdate();
}

// Keep for backward compatibility
function finToggle() {}
function finMonthlyToggle(enabled) { finSetMode(enabled ? 'monthly' : 'full'); }

function finPopulateSimMonths() {
  const sel      = document.getElementById('fin-sim-month');
  const deadline = document.getElementById('fin-deadline')?.value?.trim() || '';
  if (!sel) return;

  const deadlineDate = deadline ? new Date(deadline) : null;
  const now     = new Date();
  const months  = [];
  const curVal  = sel.value; // preserve selection

  for (let i = 0; i < 24; i++) {
    const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
    // Stop before deadline month
    if (deadlineDate && d >= deadlineDate) break;
    months.push({ label: d.toLocaleDateString('en-US', { month:'long', year:'numeric' }), date: d });
  }

  sel.innerHTML = months.map((m, i) =>
    `<option value="${i}">${m.label}${i===0?' (Today)':''}</option>`).join('');
  sel._monthDates = months.map(m => m.date);

  // Restore previous selection if still valid
  if (curVal && parseInt(curVal) < months.length) sel.value = curVal;
}

function finPreviewUpdate() {
  if (!_finMonthly) return;
  const fee      = parseFloat(document.getElementById('fin-fee')?.value) || 0;
  const deadline = document.getElementById('fin-deadline')?.value?.trim() || '';
  const rowsEl   = document.getElementById('fin-plan-rows');
  const noteEl   = document.getElementById('fin-deposit-note');
  if (!rowsEl) return;

  if (!fee || !deadline) {
    rowsEl.innerHTML = '<div class="fin-plan-empty">Fill in fee and deadline to see preview</div>';
    return;
  }

  // Populate months if not already populated or deadline changed
  const sel = document.getElementById('fin-sim-month');
  const prevCount = sel?._monthDates?.length || 0;
  finPopulateSimMonths();
  const simIdx = sel ? parseInt(sel.value) || 0 : 0;
  const fromDate = sel?._monthDates?.[simIdx] || new Date();

  const depAmt   = _finDepositEnabled ? (parseFloat(document.getElementById('fin-deposit-amt')?.value)||250) : 0;
  const planBase = _finDepositEnabled ? Math.max(0, fee - depAmt) : fee;

  // Show deposit note
  if (noteEl) {
    if (_finDepositEnabled && depAmt > 0) {
      noteEl.style.display = 'block';
      noteEl.innerHTML = `
        <strong>Deposit:</strong> $${depAmt.toFixed(2)} due at registration to secure spot &nbsp;|&nbsp;
        <strong>Remaining:</strong> $${planBase.toFixed(2)} split across monthly payments below`;
    } else {
      noteEl.style.display = 'none';
    }
  }

  const plan = generatePaymentPlan(planBase, deadline, fromDate);

  if (!plan.length) {
    rowsEl.innerHTML = '<div class="fin-plan-empty">No months available — choose an earlier registration month</div>';
    return;
  }

  const fmt2 = n => '$' + n.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  rowsEl.innerHTML = plan.map(p =>
    `<div class="fin-plan-row">
      <span class="fin-plan-month">${p.month}</span>
      <span class="fin-plan-amount">${fmt2(p.amount)}</span>
    </div>`).join('') +
    `<div class="fin-plan-row" style="border-top:1px solid rgba(255,255,255,.25);margin-top:.3rem;padding-top:.6rem">
      <span class="fin-plan-month" style="color:rgba(255,255,255,.9);font-weight:600">
        ${_finDepositEnabled ? `Monthly Total (after $${depAmt.toFixed(2)} deposit)` : 'Total'}
      </span>
      <span class="fin-plan-amount" style="color:#ffd700">${fmt2(planBase)}</span>
    </div>`;
}

function generatePaymentPlan(fee, deadlineStr, fromDate) {
  const deadline = new Date(deadlineStr);
  if (isNaN(deadline) || deadline <= fromDate) return [];
  const months = [];
  const cur = new Date(fromDate.getFullYear(), fromDate.getMonth(), 1);
  const end = new Date(deadline.getFullYear(), deadline.getMonth(), 1);
  while (cur <= end) {
    months.push(new Date(cur));
    cur.setMonth(cur.getMonth() + 1);
  }
  if (!months.length) return [];
  const perMonth = fee / months.length;
  return months.map(d => ({
    month:  d.toLocaleDateString('en-US', { month:'long', year:'numeric' }),
    amount: parseFloat(perMonth.toFixed(2)),
    paid:   false,
  }));
}

async function saveFinancials() {
  const fee      = parseFloat(document.getElementById('fin-fee')?.value) || 0;
  const deadline = document.getElementById('fin-deadline')?.value?.trim() || '';
  const depAmt   = _finDepositEnabled ? (parseFloat(document.getElementById('fin-deposit-amt')?.value) || 250) : 0;
  if (!fee) { showMsg('msg-financials', 'Please enter a player fee amount.', 'error'); return; }
  if (!deadline) { showMsg('msg-financials', 'Please select a payment deadline.', 'error'); return; }

  setLoading('save-fin-btn', 'save-fin-txt', true);
  try {
    const res  = await fetch(`${API_BASE}/api/coach/financials`, {
      method: 'POST', headers: authH(),
      body: JSON.stringify({
        playerFee:       fee,
        paymentDeadline: deadline,
        fullPayOnly:     _finFullPay,
        depositEnabled:  _finDepositEnabled,
        depositAmount:   depAmt,
        monthlyPayments: _finMonthly,
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    _finSetup = data.financials;
    finShowLocked();
  } catch(err) { showMsg('msg-financials', err.message, 'error'); }
  finally { setLoading('save-fin-btn', 'save-fin-txt', false, 'Save Financial Setup'); }
}

function finShowLocked() {
  const f = _finSetup;
  if (!f) return;
  const fmt2 = n => '$' + (parseFloat(n)||0).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const modeLabel    = f.monthly_payments ? 'Monthly Payments' : 'Full Payment';
  const depositLabel = f.deposit_enabled  ? 'Yes \u2014 ' + fmt2(f.deposit_amount) : 'No';

  const lockedHtml = `
    <div id="fin-locked-view">
      <div class="msg success" style="display:block;margin-bottom:1.1rem">Financial setup saved! &#10003;</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:1.2rem">
        <div style="background:var(--light);border-radius:8px;padding:.9rem 1.1rem">
          <div style="font-size:.62rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.4rem">Player Fee</div>
          <div style="font-family:'Oswald',sans-serif;font-size:1.4rem;font-weight:700;color:var(--navy)">${fmt2(f.player_fee)}</div>
        </div>
        <div style="background:var(--light);border-radius:8px;padding:.9rem 1.1rem">
          <div style="font-size:.62rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.4rem">Payment Deadline</div>
          <div style="font-family:'Oswald',sans-serif;font-size:.95rem;font-weight:700;color:var(--navy)">${esc(f.payment_deadline||'\u2014')}</div>
        </div>
        <div style="background:var(--light);border-radius:8px;padding:.9rem 1.1rem">
          <div style="font-size:.62rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.4rem">Payment Mode</div>
          <div style="font-family:'Oswald',sans-serif;font-size:.95rem;font-weight:700;color:var(--navy)">${modeLabel}</div>
        </div>
        <div style="background:var(--light);border-radius:8px;padding:.9rem 1.1rem">
          <div style="font-size:.62rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.4rem">Deposit</div>
          <div style="font-family:'Oswald',sans-serif;font-size:.95rem;font-weight:700;color:var(--navy)">${depositLabel}</div>
        </div>
      </div>
      <button onclick="finShowEdit()" style="display:inline-flex;align-items:center;gap:.5rem;background:none;border:1.5px solid var(--mid);border-radius:8px;padding:10px 22px;font-family:'Oswald',sans-serif;font-size:.82rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--navy);cursor:pointer">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Edit Financial Setup
      </button>
    </div>`;

  const cardBody = document.querySelector('#panel-financials .card .card-body');
  if (cardBody) {
    const existing = document.getElementById('fin-locked-view');
    if (existing) existing.remove();
    Array.from(cardBody.children).forEach(el => { el.style.display = 'none'; });
    cardBody.insertAdjacentHTML('beforeend', lockedHtml);
  }
}

function finShowEdit() {
  const locked = document.getElementById('fin-locked-view');
  if (locked) locked.remove();
  const cardBody = document.querySelector('#panel-financials .card .card-body');
  if (cardBody) {
    Array.from(cardBody.children).forEach(el => { el.style.display = ''; });
  }
}

async function loadFinancials() {
  try {
    const [finRes, payRes] = await Promise.all([
      fetch(`${API_BASE}/api/coach/financials`, { headers: authH() }),
      fetch(`${API_BASE}/api/coach/player-payments`, { headers: authH() }),
    ]);
    const finData = await finRes.json();
    const payData = await payRes.json();
    _finSetup       = finData.financials || null;
    _playerPayments = payData.payments   || [];

    if (_finSetup) {
      const f = _finSetup;
      document.getElementById('fin-fee').value      = f.player_fee || '';
      document.getElementById('fin-deadline').value = f.payment_deadline || '';
      // Re-init flatpickr on deadline
      setTimeout(() => {
        const fp = flatpickr('#fin-deadline', { dateFormat: 'F j, Y', allowInput: false, disableMobile: true });
        if (f.payment_deadline) fp.setDate(f.payment_deadline, false);
      }, 50);
      _finFullPay        = f.full_pay_only;
      _finDepositEnabled = f.deposit_enabled;
      _finMonthly        = f.monthly_payments;
      finSetMode(_finMonthly ? 'monthly' : 'full');
      finDepositToggle(_finDepositEnabled);
      if (f.deposit_amount) document.getElementById('fin-deposit-amt').value = f.deposit_amount;
      finPreviewUpdate();
      setTimeout(() => finShowLocked(), 120);
    }

    // Fallback — if player fee is still empty, pre-fill from published budget
    // Handles: new coach who published but hasn't set up financials yet,
    // or existing coach who cancelled the confirm dialog
    const feeEl = document.getElementById('fin-fee');
    if (!feeEl.value) {
      const published = _savedBudgets.find(b => b.status === 'published');
      if (published && published.per_player) {
        feeEl.value = published.per_player;
      }
    }
    renderARTable();
  } catch(err) { console.error('loadFinancials:', err); }
}

function renderARTable() {
  const tbody  = document.getElementById('ar-table-body');
  const fmt2   = n => '$' + (parseFloat(n)||0).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  if (!tbody) return;

  // Update summary stats
  const _paidPayments = _playerPayments.filter(p => p.status === 'Paid' || p.status === 'Partial');
  const total      = _paidPayments.length;
  const expected   = _paidPayments.reduce((s, p) => s + (parseFloat(p.total_fee)||0), 0);
  const collected  = _paidPayments.reduce((s, p) => s + (parseFloat(p.amount_paid)||0), 0);
  const outstanding = expected - collected;
  const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setEl('fin-stat-players',     total);
  setEl('fin-stat-expected',    fmt2(expected));
  setEl('fin-stat-collected',   fmt2(collected));
  setEl('fin-stat-outstanding', fmt2(outstanding));

  if (!_playerPayments.length) {
    tbody.innerHTML = '<tr><td colspan="9"><div class="no-ar-state">No player payment records yet. Players will appear here when they register.</div></td></tr>';
    return;
  }

  tbody.innerHTML = _playerPayments.filter(p => p.status === 'Paid' || p.status === 'Partial').map(p => {
    const statusClass = p.status === 'Paid' ? 'paid' : p.status === 'Partial' ? 'partial' : 'pending';
    const depHtml = p.deposit_amount > 0
      ? (p.deposit_paid
          ? `<span class="ar-status paid">Paid</span>`
          : `<span class="ar-status pending">Not Paid</span>`)
      : '—';
    return `
      <tr>
        <td>${esc(p.player_name||'—')}</td>
        <td style="font-size:.76rem;color:var(--sub)">${esc(p.registered_date||'—')}</td>
        <td>${fmt2(p.total_fee)}</td>
        <td>${depHtml}</td>
        <td>${fmt2(p.amount_paid)}</td>
        <td style="font-weight:700;color:${parseFloat(p.balance)>0?'var(--red)':'#16a34a'}">${fmt2(p.balance)}</td>
        <td style="font-size:.76rem;color:var(--sub)">${esc(p.payment_deadline||'—')}</td>
        <td><span class="ar-status ${statusClass}">${esc(p.status)}</span></td>
        <td>
          <button class="ar-mark-btn" onclick="openPaymentDetail('${p._id}')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            View Plan
          </button>
        </td>
      </tr>`;
  }).join('');
}



function openPaymentDetail(paymentId) {
  const p = _playerPayments.find(x => x._id === paymentId);
  if (!p) return;
  document.getElementById('pd-modal-title').textContent = (p.player_name||'Player') + ' — Payment Plan';
  const fmt2 = n => '$' + (parseFloat(n)||0).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const plan = p.payment_plan || [];

  let planHtml = '';
  if (plan.length) {
    planHtml = plan.map((item) => `
      <div class="plan-detail-item ${item.paid ? 'paid-item' : ''}">
        <span>${esc(item.month)}</span>
        <div style="display:flex;align-items:center;gap:.6rem">
          <span style="font-weight:700">${fmt2(item.amount)}</span>
          <span class="ar-status ${item.paid ? 'paid' : 'pending'}" style="font-size:.68rem">${item.paid ? 'Paid' : 'Pending'}</span>
        </div>
      </div>`).join('');
  } else {
    planHtml = '<div style="color:var(--sub);font-size:.84rem;padding:.5rem">No monthly plan — full payment expected by deadline.</div>';
  }

  document.getElementById('pd-modal-body').innerHTML = `
    <div style="padding:.5rem 0">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:1.2rem">
        <div style="background:var(--light);border-radius:6px;padding:.75rem 1rem">
          <div style="font-size:.62rem;color:var(--sub);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.3rem">Total Fee</div>
          <div style="font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:var(--navy)">${fmt2(p.total_fee)}</div>
        </div>
        <div style="background:var(--light);border-radius:6px;padding:.75rem 1rem">
          <div style="font-size:.62rem;color:var(--sub);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.3rem">Balance</div>
          <div style="font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:${parseFloat(p.balance)>0?'var(--red)':'#16a34a'}">${fmt2(p.balance)}</div>
        </div>
        <div style="background:var(--light);border-radius:6px;padding:.75rem 1rem">
          <div style="font-size:.62rem;color:var(--sub);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.3rem">Amount Paid</div>
          <div style="font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:#16a34a">${fmt2(p.amount_paid)}</div>
        </div>
        <div style="background:var(--light);border-radius:6px;padding:.75rem 1rem">
          <div style="font-size:.62rem;color:var(--sub);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.3rem">Deadline</div>
          <div style="font-family:'Oswald',sans-serif;font-size:.9rem;font-weight:700;color:var(--navy)">${esc(p.payment_deadline||'—')}</div>
        </div>
      </div>
      ${p.deposit_amount > 0 ? `
        <div style="background:${p.deposit_paid?'#f0fdf4':'#fffbea'};border-radius:6px;padding:.75rem 1rem;margin-bottom:1rem;border:1px solid ${p.deposit_paid?'#bbf7d0':'#fde68a'}">
          <div style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.2rem;color:${p.deposit_paid?'#16a34a':'#92400e'}">Deposit — ${fmt2(p.deposit_amount)}</div>
          <div style="font-size:.82rem;color:${p.deposit_paid?'#16a34a':'var(--sub)'}">
            ${p.deposit_paid ? '✓ Paid on ' + (p.deposit_paid_date||'') : 'Not yet paid'}
          </div>
        </div>` : ''}
      <div style="font-size:.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.6rem">Monthly Payment Schedule</div>
      <div class="plan-detail-wrap">${planHtml}</div>
    </div>`;

  document.getElementById('payment-detail-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}



function closePaymentDetail() {
  document.getElementById('payment-detail-overlay').classList.remove('open');
  document.body.style.overflow = '';
}

/* ── COST CALCULATOR ── */
let _otherCount = 0;

function fmt(n) { return '$' + n.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
function val(id) { return parseFloat(document.getElementById(id)?.value) || 0; }

function addOther() {
  const wrap = document.getElementById('calc-other-wrap');
  if (!wrap) return;
  const idx = _otherCount++;
  const row = document.createElement('div');
  row.className = 'calc-other-row';
  row.id = 'calc-other-row-' + idx;
  row.innerHTML = `
    <div class="calc-field"><label class="calc-label">Description</label><input class="calc-input" type="text" id="calc-other-desc-${idx}" placeholder="e.g. Field fees" oninput="calcUpdate()"></div>
    <div class="calc-field"><label class="calc-label">Amount</label><div class="calc-prefix"><input class="calc-input" type="number" id="calc-other-amt-${idx}" placeholder="0" min="0" oninput="calcUpdate()"></div></div>
    <div style="padding-top:1.4rem"><button class="calc-remove-btn" onclick="removeOther(${idx})" title="Remove"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>`;
  wrap.appendChild(row);
  calcUpdate();
}

function removeOther(idx) {
  document.getElementById('calc-other-row-' + idx)?.remove();
  calcUpdate();
}

function calcUpdate() {
  // User changed a field — allow saving again
  _budgetSaved = false;
  const btn = document.getElementById('save-budget-btn');
  const txt = document.getElementById('save-budget-txt');
  if (btn) { btn.disabled = false; btn.style.background = ''; }
  if (txt && txt.textContent === 'Saved! ✓') txt.textContent = 'Save as Draft';
  const tournaments = val('calc-num-events') * val('calc-event-cost');
  const head        = val('calc-head-pay');
  const asst        = val('calc-asst-pay');
  const rentals     = val('calc-rentals');
  const hotels      = val('calc-hotel-nights') * val('calc-hotel-avg');
  const gas         = val('calc-gas');
  const uniforms    = val('calc-uniforms') * val('calc-uniform-cost');
  const equipment   = val('calc-equipment');
  const insurance   = val('calc-insurance');
  const ambassadors = 450 * val('calc-players'); // Ambassadors Baseball fee (per player)

  // Other expenses
  let otherTotal = 0;
  let otherRowsHtml = '';
  document.querySelectorAll('[id^="calc-other-amt-"]').forEach(el => {
    const idx   = el.id.replace('calc-other-amt-', '');
    const amt   = parseFloat(el.value) || 0;
    const desc  = document.getElementById('calc-other-desc-' + idx)?.value.trim() || 'Other';
    otherTotal += amt;
    if (amt > 0) {
      otherRowsHtml += `<div class="calc-total-row"><span class="calc-total-label">${esc(desc)}</span><span class="calc-total-value">${fmt(amt)}</span></div>`;
    }
  });

  const total   = tournaments + head + asst + rentals + hotels + gas + uniforms + equipment + insurance + ambassadors + otherTotal;
  const players = val('calc-players');
  const perPlayer = players > 0 ? total / players : 0;

  // Update totals
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = fmt(v); };
  set('ct-tournaments', tournaments);
  set('ct-head', head);
  set('ct-asst', asst);
  set('ct-rentals', rentals);
  set('ct-hotels', hotels);
  set('ct-gas', gas);
  set('ct-uniforms', uniforms);
  set('ct-equipment', equipment);
  set('ct-insurance', insurance);
  set('ct-ambassadors', ambassadors);
  set('ct-total', total);
  set('ct-player-fee', perPlayer);

  const otherEl = document.getElementById('ct-other-rows');
  if (otherEl) otherEl.innerHTML = otherRowsHtml;
}

function calcReset() {
  if (!confirm('Reset all calculator fields?')) return;
  ['calc-players','calc-seasons','calc-num-events','calc-event-cost','calc-head-pay','calc-asst-pay',
   'calc-rentals','calc-gas','calc-hotel-nights','calc-hotel-avg','calc-uniforms','calc-uniform-cost',
   'calc-equipment','calc-insurance'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });

  const wrap = document.getElementById('calc-other-wrap');
  if (wrap) wrap.innerHTML = '';
  _otherCount = 0;
  calcUpdate();
}

/* ── BUDGET SAVE / VIEW / DELETE ── */
let _savedBudgets = [];

let _budgetSaved = false;

async function saveBudgetAsDraft() {
  const total     = parseFloat(document.getElementById('ct-total')?.textContent?.replace(/[$,]/g,'')) || 0;
  const perPlayer = parseFloat(document.getElementById('ct-player-fee')?.textContent?.replace(/[$,]/g,'')) || 0;
  if (total === 0) { alert('Please fill in the calculator before saving.'); return; }

  const others = [];
  document.querySelectorAll('[id^="calc-other-amt-"]').forEach(el => {
    const idx  = el.id.replace('calc-other-amt-','');
    const amt  = parseFloat(el.value)||0;
    const desc = document.getElementById('calc-other-desc-'+idx)?.value.trim()||'Other';
    if (amt > 0) others.push({ desc, amt });
  });

  const payload = {
    date:        new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' }),
    players:     val('calc-players'),
    seasons:     val('calc-seasons'),
    numEvents:   val('calc-num-events'),
    eventCost:   val('calc-event-cost'),
    tournaments: val('calc-num-events') * val('calc-event-cost'),
    headPay:     val('calc-head-pay'),
    asstPay:     val('calc-asst-pay'),
    rentals:     val('calc-rentals'),
    gas:         val('calc-gas'),
    hotelNights: val('calc-hotel-nights'),
    hotelAvg:    val('calc-hotel-avg'),
    hotels:      val('calc-hotel-nights') * val('calc-hotel-avg'),
    numUniforms: val('calc-uniforms'),
    uniformCost: val('calc-uniform-cost'),
    uniforms:    val('calc-uniforms') * val('calc-uniform-cost'),
    equipment:   val('calc-equipment'),
    insurance:   val('calc-insurance'),
    ambassadors: 450 * val('calc-players'),
    others,
    total,
    perPlayer,
    status:      'draft',
  };

  const btn = document.getElementById('save-budget-btn');
  const txt = document.getElementById('save-budget-txt');
  btn.disabled = true;
  txt.innerHTML = '<span class="btn-spinner"></span>';

  try {
    let res;
    if (_editingBudgetId) {
      res = await fetch(`${API_BASE}/api/coach/budgets/${_editingBudgetId}`, {
        method: 'PUT', headers: authH(), body: JSON.stringify(payload)
      });
    } else {
      res = await fetch(`${API_BASE}/api/coach/budgets`, {
        method: 'POST', headers: authH(), body: JSON.stringify(payload)
      });
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to save');
    _editingBudgetId = null;
    txt.textContent = 'Saved! ✓';
    btn.style.background = '#16a34a';
    const cancelBtn = document.getElementById('cancel-edit-budget-btn');
    if (cancelBtn) cancelBtn.style.display = 'none';
    setTimeout(() => { txt.textContent = 'Save as Draft'; btn.style.background = ''; btn.disabled = false; }, 2000);
    await loadBudgetsLocal();
  } catch(err) {
    alert('Error: ' + err.message);
    txt.textContent = 'Save as Draft';
    btn.disabled = false;
  }
}

async function publishBudgetFromForm() {
  const total     = parseFloat(document.getElementById('ct-total')?.textContent?.replace(/[$,]/g,'')) || 0;
  const perPlayer = parseFloat(document.getElementById('ct-player-fee')?.textContent?.replace(/[$,]/g,'')) || 0;
  if (total === 0) { alert('Please fill in the calculator before publishing.'); return; }

  const others = [];
  document.querySelectorAll('[id^="calc-other-amt-"]').forEach(el => {
    const idx  = el.id.replace('calc-other-amt-','');
    const amt  = parseFloat(el.value)||0;
    const desc = document.getElementById('calc-other-desc-'+idx)?.value.trim()||'Other';
    if (amt > 0) others.push({ desc, amt });
  });

  const payload = {
    date:        new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' }),
    players:     val('calc-players'),
    seasons:     val('calc-seasons'),
    numEvents:   val('calc-num-events'),
    eventCost:   val('calc-event-cost'),
    tournaments: val('calc-num-events') * val('calc-event-cost'),
    headPay:     val('calc-head-pay'),
    asstPay:     val('calc-asst-pay'),
    rentals:     val('calc-rentals'),
    gas:         val('calc-gas'),
    hotelNights: val('calc-hotel-nights'),
    hotelAvg:    val('calc-hotel-avg'),
    hotels:      val('calc-hotel-nights') * val('calc-hotel-avg'),
    numUniforms: val('calc-uniforms'),
    uniformCost: val('calc-uniform-cost'),
    uniforms:    val('calc-uniforms') * val('calc-uniform-cost'),
    equipment:   val('calc-equipment'),
    insurance:   val('calc-insurance'),
    ambassadors: 450 * val('calc-players'),
    others,
    total,
    perPlayer,
    status:      'published',
  };

  const publishBtn = document.getElementById('publish-budget-form-btn');
  if (publishBtn) { publishBtn.disabled = true; publishBtn.textContent = 'Publishing…'; }

  try {
    let res;
    if (_editingBudgetId) {
      res = await fetch(`${API_BASE}/api/coach/budgets/${_editingBudgetId}`, {
        method: 'PUT', headers: authH(), body: JSON.stringify(payload)
      });
    } else {
      res = await fetch(`${API_BASE}/api/coach/budgets`, {
        method: 'POST', headers: authH(), body: JSON.stringify(payload)
      });
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to publish');
    _editingBudgetId = null;
    const cancelBtn = document.getElementById('cancel-edit-budget-btn');
    if (cancelBtn) cancelBtn.style.display = 'none';
    await updateFinancialPlayerFee(perPlayer);
    await loadBudgetsLocal();
  } catch(err) {
    alert('Error: ' + err.message);
  } finally {
    if (publishBtn) { publishBtn.disabled = false; publishBtn.textContent = 'Publish'; }
  }
}

async function publishBudgetFromCard(id) {
  const b = _savedBudgets.find(x => x._id === id);
  if (!b) return;

  const payload = {
    date:        b.date,
    players:     b.players,
    seasons:     b.seasons,
    numEvents:   b.num_events,
    eventCost:   b.event_cost,
    tournaments: b.tournaments,
    headPay:     b.head_pay,
    asstPay:     b.asst_pay,
    rentals:     b.rentals,
    gas:         b.gas,
    hotelNights: b.hotel_nights,
    hotelAvg:    b.hotel_avg,
    hotels:      b.hotels,
    numUniforms: b.num_uniforms,
    uniformCost: b.uniform_cost,
    uniforms:    b.uniforms,
    equipment:   b.equipment,
    insurance:   b.insurance,
    ambassadors: b.ambassadors,
    others:      b.others || [],
    total:       b.total,
    perPlayer:   b.per_player,
    status:      'published',
  };

  try {
    const res = await fetch(`${API_BASE}/api/coach/budgets/${id}`, {
      method: 'PUT', headers: authH(), body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to publish');
    await updateFinancialPlayerFee(b.per_player || 0);
    await loadBudgetsLocal();
  } catch(err) { alert('Error: ' + err.message); }
}

let _publishConfirmCallback = null;

function showPublishConfirm(msg, onConfirm) {
  _publishConfirmCallback = () => {
    closePublishConfirm();
    onConfirm();
  };
  document.getElementById('publish-confirm-msg').innerHTML = msg;
  document.getElementById('publish-confirm-overlay').classList.add('open');
}

function closePublishConfirm() {
  document.getElementById('publish-confirm-overlay').classList.remove('open');
  _publishConfirmCallback = null;
}

async function updateFinancialPlayerFee(fee) {
  const newFee = Math.round(fee * 100) / 100;
  const fmtFee = n => '$' + Number(n).toLocaleString('en-US', { minimumFractionDigits:2, maximumFractionDigits:2 });

  // Always pre-fill the Team Financials player fee input in the DOM
  const feeInput = document.getElementById('fin-fee');
  if (feeInput) feeInput.value = newFee;

  // Check existing financials
  try {
    const res = await fetch(`${API_BASE}/api/coach/financials`, { headers: authH() });
    if (!res.ok) return;
    const data = await res.json();
    const f = data.financials;

    // New coach — no financials or no deadline set yet
    // Skip backend write entirely, DOM input is already pre-filled above
    if (!f || !f.payment_deadline) return;

    // Existing coach — build confirmation message based on whether fee is changing
    const oldFee = f.player_fee || 0;
    const feeChanged = oldFee !== newFee;

    const msg = feeChanged
      ? `Publishing this budget will update your Team Financials player fee from <strong>${fmtFee(oldFee)}</strong> to <strong>${fmtFee(newFee)}</strong>.<br><br>Because the fee is changing, your Stripe payment products will be updated to the new amount. Any payment links already sent to players will no longer work — you will need to resend them.`
      : `Publishing this budget will confirm your player fee of <strong>${fmtFee(newFee)}</strong> in Team Financials.<br><br>The fee has not changed so your existing Stripe payment products and player payment links will remain exactly as they are.`;

    showPublishConfirm(msg, async () => {
      try {
        await fetch(`${API_BASE}/api/coach/financials`, {
          method: 'POST', headers: authH(),
          body: JSON.stringify({
            playerFee:         newFee,
            paymentDeadline:   f.payment_deadline,
            fullPayOnly:       f.full_pay_only      !== false,
            depositEnabled:    !!f.deposit_enabled,
            depositAmount:     f.deposit_amount     || 250,
            monthlyPayments:   !!f.monthly_payments,
            installmentMonths: f.installment_months || 3,
          })
        });
      } catch(e) { /* silent — DOM value already set above */ }
    });
  } catch(e) { /* silent — DOM value already set above */ }
}

async function deleteBudget(id) {
  if (!confirm('Delete this saved budget?')) return;
  try {
    const res  = await fetch(`${API_BASE}/api/coach/budgets/${id}`, {
      method: 'DELETE', headers: authH()
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed');
    _savedBudgets = _savedBudgets.filter(b => b._id !== id);
    renderSavedBudgets();
  } catch(err) { alert('Error: ' + err.message); }
}

function viewBudget(id) {
  const b = _savedBudgets.find(x => x._id === id);
  if (!b) return;
  const detail = document.getElementById('budget-inline-detail');
  if (!detail) return;

  const otherRows = (b.others||[]).map(o =>
    `<tr><td>${esc(o.desc)}</td><td>${fmt(o.amt)}</td></tr>`).join('');

  detail.style.display = 'block';
  detail.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;flex-wrap:wrap;gap:.5rem">
      <div style="font-family:'Oswald',sans-serif;font-size:1rem;font-weight:700;color:var(--navy);text-transform:uppercase;letter-spacing:.04em">Budget — ${(b.updated_at && b.updated_at !== b.created_at) ? new Date(b.updated_at).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) + ' · Updated' : new Date(b.created_at).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) + ' · Created'}</div>
      <button onclick="document.getElementById('budget-inline-detail').style.display='none'" style="background:none;border:1.5px solid var(--mid);border-radius:6px;padding:5px 12px;font-family:'Oswald',sans-serif;font-size:.7rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--sub);cursor:pointer">✕ Close</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem;margin-bottom:1rem">
      <div style="background:var(--light);border-radius:6px;padding:.7rem .9rem">
        <div style="font-size:.6rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.3rem">Paying Players</div>
        <div style="font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:var(--navy)">${b.players||'—'}</div>
      </div>
      <div style="background:var(--light);border-radius:6px;padding:.7rem .9rem">
        <div style="font-size:.6rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--sub);margin-bottom:.3rem">Seasons</div>
        <div style="font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:var(--navy)">${b.seasons||'—'}</div>
      </div>
    </div>
    <table class="budget-detail-table">
      <tr><td>Tournaments / Events (${b.num_events||0} × $${b.event_cost||0})</td><td>${fmt(b.tournaments||0)}</td></tr>
      <tr><td>Head Coach Pay</td><td>${fmt(b.head_pay||0)}</td></tr>
      <tr><td>Assistant Coach Pay</td><td>${fmt(b.asst_pay||0)}</td></tr>
      <tr><td>Rentals</td><td>${fmt(b.rentals||0)}</td></tr>
      <tr><td>Hotel Costs (${b.hotel_nights||0} nights × $${b.hotel_avg||0})</td><td>${fmt(b.hotels||0)}</td></tr>
      <tr><td>Gas</td><td>${fmt(b.gas||0)}</td></tr>
      <tr><td>Coach Uniforms (${b.num_uniforms||0} × $${b.uniform_cost||0})</td><td>${fmt(b.uniforms||0)}</td></tr>
      <tr><td>Equipment</td><td>${fmt(b.equipment||0)}</td></tr>
      <tr><td>Coach Liability Insurance</td><td>${fmt(b.insurance||0)}</td></tr>
      <tr><td>Ambassadors Baseball</td><td>${fmt(b.ambassadors||0)}</td></tr>
      ${otherRows}
      <tr class="highlight"><td>Total Expenses</td><td>${fmt(b.total||0)}</td></tr>
      <tr class="grand"><td>Player Fee (Total ÷ ${b.players||0} Players)</td><td>${fmt(b.per_player||0)}</td></tr>
    </table>`;
  detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function closeBudgetView() {
  const overlay = document.getElementById('budget-view-overlay');
  if (overlay) overlay.classList.remove('open');
  document.body.style.overflow = '';
}

function addOtherExpenseField() {
  const wrap = document.getElementById('eb-other-expenses-wrap');
  if (!wrap) return;
  const idx = Date.now(); // Use timestamp as unique ID
  const newField = document.createElement('div');
  newField.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:.8rem';
  newField.innerHTML = `
    <div class="field-group"><label class="field-label">Description</label><input class="field-input eb-other-desc" data-idx="${idx}" type="text" placeholder="e.g. Travel Permits"></div>
    <div class="field-group"><label class="field-label">Amount</label><div style="position:relative"><span style="position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--sub);font-size:.88rem;pointer-events:none">$</span><input class="field-input eb-other-amt" type="number" data-idx="${idx}" min="0" style="padding-left:26px"></div></div>
  `;
  wrap.appendChild(newField);
}

let _editingBudgetId = null;

function openEditBudget(id) {
  const b = _savedBudgets.find(x => x._id === id);
  if (!b) return;
  _editingBudgetId = id;

  // Pre-fill the main calculator form with existing budget values
  const setVal = (elId, v) => { const el = document.getElementById(elId); if (el) el.value = v || ''; };
  setVal('calc-players',      b.players);
  setVal('calc-seasons',      b.seasons);
  setVal('calc-num-events',   b.num_events);
  setVal('calc-event-cost',   b.event_cost);
  setVal('calc-head-pay',     b.head_pay);
  setVal('calc-asst-pay',     b.asst_pay);
  setVal('calc-rentals',      b.rentals);
  setVal('calc-gas',          b.gas);
  setVal('calc-hotel-nights', b.hotel_nights);
  setVal('calc-hotel-avg',    b.hotel_avg);
  setVal('calc-uniforms',     b.num_uniforms);
  setVal('calc-uniform-cost', b.uniform_cost);
  setVal('calc-equipment',    b.equipment);
  setVal('calc-insurance',    b.insurance);

  // Rebuild other expenses in the calc form
  const otherWrap = document.getElementById('calc-other-wrap');
  if (otherWrap) {
    otherWrap.innerHTML = '';
    (b.others || []).forEach(o => {
      const idx = Date.now() + Math.floor(Math.random() * 10000);
      const row = document.createElement('div');
      row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr;gap:.7rem;margin-bottom:.6rem';
      row.innerHTML = `
        <div class="calc-field"><label class="calc-label">Description</label><input class="calc-input" id="calc-other-desc-${idx}" type="text" value="${esc(o.desc||'Other')}" placeholder="e.g. Travel Permits"></div>
        <div class="calc-field"><label class="calc-label">Amount</label><div class="calc-prefix"><input class="calc-input" id="calc-other-amt-${idx}" type="number" value="${o.amt||''}" min="0" oninput="calcUpdate()"></div></div>`;
      otherWrap.appendChild(row);
    });
  }

  calcUpdate();

  // Show the calculator form, hide the budget card and inline detail
  const formWrap   = document.getElementById('budget-form-wrap');
  const savedWrap  = document.getElementById('saved-budgets-wrap');
  const inlineDetail = document.getElementById('budget-inline-detail');
  if (formWrap)   formWrap.style.display   = '';
  if (savedWrap)  savedWrap.style.display  = 'none';
  if (inlineDetail) inlineDetail.style.display = 'none';

  // Update button labels — always Save as Draft
  const txt = document.getElementById('save-budget-txt');
  if (txt) txt.textContent = 'Save as Draft';
  const cancelBtn = document.getElementById('cancel-edit-budget-btn');
  if (cancelBtn) cancelBtn.style.display = '';

  formWrap?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function cancelEditBudget() {
  _editingBudgetId = null;
  const txt = document.getElementById('save-budget-txt');
  if (txt) txt.textContent = 'Save as Draft';
  const cancelBtn = document.getElementById('cancel-edit-budget-btn');
  if (cancelBtn) cancelBtn.style.display = 'none';
  const formWrap = document.getElementById('budget-form-wrap');
  if (formWrap) formWrap.style.display = 'none';
  const savedWrap = document.getElementById('saved-budgets-wrap');
  if (savedWrap) savedWrap.style.display = '';
  if (_savedBudgets.length) viewBudget(_savedBudgets[0]._id);
}

async function saveEditBudget() {
  if (!_editingBudgetId) return;
  
  const payload = {
    players:     parseInt(document.getElementById('eb-players').value) || 0,
    seasons:     parseInt(document.getElementById('eb-seasons').value) || 0,
    numEvents:   parseInt(document.getElementById('eb-num-events').value) || 0,
    eventCost:   parseFloat(document.getElementById('eb-event-cost').value) || 0,
    tournaments: parseInt(document.getElementById('eb-num-events').value) * parseFloat(document.getElementById('eb-event-cost').value) || 0,
    headPay:     parseFloat(document.getElementById('eb-head-pay').value) || 0,
    asstPay:     parseFloat(document.getElementById('eb-asst-pay').value) || 0,
    rentals:     parseFloat(document.getElementById('eb-rentals').value) || 0,
    gas:         parseFloat(document.getElementById('eb-gas').value) || 0,
    hotelNights: parseInt(document.getElementById('eb-hotel-nights').value) || 0,
    hotelAvg:    parseFloat(document.getElementById('eb-hotel-avg').value) || 0,
    hotels:      parseInt(document.getElementById('eb-hotel-nights').value) * parseFloat(document.getElementById('eb-hotel-avg').value) || 0,
    numUniforms: parseInt(document.getElementById('eb-uniforms').value) || 0,
    uniformCost: parseFloat(document.getElementById('eb-uniform-cost').value) || 0,
    uniforms:    parseInt(document.getElementById('eb-uniforms').value) * parseFloat(document.getElementById('eb-uniform-cost').value) || 0,
    equipment:   parseFloat(document.getElementById('eb-equipment').value) || 0,
    insurance:   parseFloat(document.getElementById('eb-insurance').value) || 0,
    ambassadors: 450 * (parseInt(document.getElementById('eb-players').value) || 0)
  };
  
  // Capture other expenses
  const others = [];
  document.querySelectorAll('.eb-other-desc').forEach(el => {
    const idx = el.getAttribute('data-idx');
    const desc = el.value.trim() || 'Other';
    const amtEl = document.querySelector(`.eb-other-amt[data-idx="${idx}"]`);
    const amt = parseFloat(amtEl?.value) || 0;
    if (amt > 0) others.push({ desc, amt });
  });
  payload.others = others;
  
  // Calculate total and per player
  let otherTotal = others.reduce((sum, o) => sum + o.amt, 0);
  payload.total = payload.tournaments + payload.headPay + payload.asstPay + payload.rentals + 
                  payload.gas + payload.hotels + payload.uniforms + payload.equipment + 
                  payload.insurance + payload.ambassadors + otherTotal;
  payload.perPlayer = payload.players > 0 ? payload.total / payload.players : 0;
  
  try {
    const res = await fetch(`${API_BASE}/api/coach/budgets/${_editingBudgetId}`, {
      method: 'PUT', headers: authH(), body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Failed to save');
    document.getElementById('budget-inline-detail').style.display = 'none';
    await loadBudgetsLocal();
  } catch(err) {
    alert('Error: ' + err.message);
  }
}

function renderSavedBudgets() {
  const wrap       = document.getElementById('saved-budgets-wrap');
  const formWrap   = document.getElementById('budget-form-wrap');
  const inlineDetail = document.getElementById('budget-inline-detail');
  if (!wrap) return;

  if (!_savedBudgets.length) {
    // No budget — show the calculator form so they can create one
    if (formWrap) formWrap.style.display = '';
    wrap.innerHTML = '';
    if (inlineDetail) inlineDetail.style.display = 'none';
    _editingBudgetId = null;
    const txt = document.getElementById('save-budget-txt');
    if (txt) txt.textContent = 'Save as Draft';
    const cancelBtn = document.getElementById('cancel-edit-budget-btn');
    if (cancelBtn) cancelBtn.style.display = 'none';
    return;
  }

  // Budget exists — hide the calculator form, show the single budget card
  if (formWrap) formWrap.style.display = 'none';
  wrap.style.display = '';
  const b = _savedBudgets[0];
  const isDraft = !b.status || b.status === 'draft';
  wrap.innerHTML = `
    <div class="budget-card">
      <div class="budget-card-info">
        <div class="budget-card-date">${(b.updated_at && b.updated_at !== b.created_at) ? new Date(b.updated_at).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) + ' · Updated' : new Date(b.created_at).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}) + ' · Created'}</div>
        <div class="budget-card-players">${b.players||0} Paying Players</div>
        <div class="budget-card-total">${fmt(parseFloat(b.total)||0)} Total Expenses</div>
        <div class="budget-card-fee">Player Fee: ${fmt(parseFloat(b.per_player)||0)} / player</div>
      </div>
      <div class="budget-card-actions">
        ${isDraft ? `
        <button class="budget-view-btn" onclick="openEditBudget('${b._id}')" style="background:var(--navy);border-color:var(--navy)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit Draft
        </button>
        <button class="budget-publish-btn" onclick="publishBudgetFromCard('${b._id}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12l5 5L20 7"/></svg>
          Publish
        </button>
        ` : `
        <button class="budget-view-btn" onclick="openEditBudget('${b._id}')" style="background:var(--navy);border-color:var(--navy)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          Edit
        </button>
        `}
      </div>
    </div>`;

  // Auto-show view detail below the card by default
  viewBudget(b._id);
}

async function loadBudgetsLocal() {
  calcUpdate();
  try {
    const res  = await fetch(`${API_BASE}/api/coach/budgets`, { headers: authH() });
    const data = await res.json();
    _savedBudgets = data.budgets || [];
    renderSavedBudgets();
  } catch(err) {
    console.error('Failed to load budgets:', err);
  }
}

loadDashboard();
</script>

<!-- EDIT PLAYER MODAL -->
<div class="edit-overlay" id="edit-overlay">
  <div class="edit-modal">
    <div class="edit-modal-head">
      <h3>Edit Player</h3>
      <button class="edit-modal-close" onclick="closeEditModal()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    </div>
    <div class="edit-modal-body">
      <div class="edit-modal-grid">
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Player Name</label>
          <input class="field-input" type="text" id="ep-name" placeholder="Full Name">
        </div>
        <div class="field-group">
          <label class="field-label">Jersey #</label>
          <input class="field-input" type="text" id="ep-jersey" placeholder="e.g. 12">
        </div>
        <div class="field-group">
          <label class="field-label">Grad Year</label>
          <input class="field-input" type="text" id="ep-gradyear" placeholder="e.g. 2026">
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Position</label>
          <select class="field-select" id="ep-position">
            <option value="">Select position</option>
            <option value="OF">OF</option>
            <option value="INF">INF</option>
            <option value="C">C</option>
            <option value="RHP">RHP</option>
            <option value="LHP">LHP</option>
          </select>
        </div>
        <div class="field-group">
          <label class="field-label">HT / WT</label>
          <input class="field-input" type="text" id="ep-hw" placeholder="e.g. 6'0 / 185lb">
        </div>
        <div class="field-group">
          <label class="field-label">City</label>
          <input class="field-input" type="text" id="ep-city" placeholder="City">
        </div>
        <div class="field-group">
          <label class="field-label">State</label>
          <input class="field-input" type="text" id="ep-state" placeholder="e.g. TN" maxlength="2">
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Email</label>
          <input class="field-input" type="email" id="ep-email" placeholder="email@example.com">
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Cell Phone</label>
          <input class="field-input" type="tel" id="ep-cell" placeholder="(000) 000-0000">
        </div>
      </div>
    </div>
    <div class="edit-modal-foot">
      <button class="edit-cancel-btn" onclick="closeEditModal()">Cancel</button>
      <button class="edit-save-btn" id="ep-save-btn" onclick="saveEditPlayer()">Save Changes</button>
    </div>
  </div>
</div>

<!-- EDIT GAME MODAL -->
<div class="edit-overlay" id="sched-edit-overlay">
  <div class="edit-modal">
    <div class="edit-modal-head">
      <h3>Edit Game / Event</h3>
      <button class="edit-modal-close" onclick="closeEditGameModal()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    </div>
    <div class="edit-modal-body">
      <input type="hidden" id="eg-id">
      <div class="edit-modal-grid">
        <div class="field-group">
          <label class="field-label">Start Date</label>
          <div class="date-input-wrap"><input class="field-input" type="text" id="eg-start-date" placeholder="e.g. June 14, 2026"><span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg></span></div>
        </div>
        <div class="field-group">
          <label class="field-label">End Date</label>
          <div class="date-input-wrap"><input class="field-input" type="text" id="eg-end-date" placeholder="e.g. June 15, 2026"><span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg></span></div>
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Event Name</label>
          <input class="field-input" type="text" id="eg-event" placeholder="e.g. vs. Nashville Elite 17U">
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">City</label>
          <input class="field-input" type="text" id="eg-city" placeholder="e.g. Nashville">
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">State</label>
          <input class="field-input" type="text" id="eg-state" placeholder="e.g. TN" maxlength="2">
        </div>
      </div>
    </div>
    <div class="edit-modal-foot">
      <button class="edit-cancel-btn" onclick="closeEditGameModal()">Cancel</button>
      <button class="edit-save-btn" id="eg-save-btn" onclick="saveEditGame()">Save Changes</button>
    </div>
  </div>
</div>

    <!-- FINANCIAL DASHBOARD PANEL -->
    <div class="dash-panel" id="panel-findashboard">
      <div id="cfd-content">
        <div style="text-align:center;padding:3rem;color:var(--sub);">Loading financial data…</div>
      </div>
    </div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/flatpickr/4.6.13/flatpickr.min.js"></script>
<script>
// ════════════════════════════════════════════════════════
//  COACH FINANCIAL DASHBOARD
//  Uses existing: API_BASE, token, authH()
// ════════════════════════════════════════════════════════

let _cfdLoaded = false;
let _cfdPag = { page: 1, perPage: 20 };

async function cfdApiFetch(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000); // 10s timeout
  try {
    const res = await fetch(`${API_BASE}${path}`, { headers: authH(), signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) { const b = await res.json().catch(()=>({})); throw new Error(b.message || `Request failed (${res.status})`); }
    return res.json();
  } catch(e) {
    clearTimeout(timer);
    if (e.name === 'AbortError') throw new Error('Request timed out — check the backend is deployed with the latest index.js');
    throw e;
  }
}

const cfdMoney = n => '$' + (Number(n)||0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const cfdDate  = s => { if (!s) return '—'; const d = new Date(s); return isNaN(d) ? '—' : d.toLocaleDateString(); };
const cfdEsc   = s => String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

async function cfdLoad() {
  if (_cfdLoaded) return;
  _cfdLoaded = true;
  const wrapper = document.getElementById('cfd-content');
  if (!wrapper) return;
  wrapper.innerHTML = '<div style="text-align:center;padding:3rem;color:var(--sub);">Loading financial data…</div>';
  try {
    const team = await cfdApiFetch('/api/coach/fin/overview');
    wrapper.innerHTML = cfdBuildHTML(team);
    cfdBindChart();
    cfdLoadPlayers();
  } catch(e) {
    _cfdLoaded = false;
    wrapper.innerHTML = '<div style="background:#fef3f5;border:1.5px solid #f5c6cb;border-radius:8px;padding:.8rem 1rem;color:var(--red);font-size:.86rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;"><span>⚠️ ' + cfdEsc(e.message||'Failed to load') + '</span><button onclick="cfdLoad()" style="background:var(--red);color:#fff;border:none;padding:5px 12px;border-radius:5px;font-family:Oswald,sans-serif;font-size:.7rem;font-weight:700;cursor:pointer;">Retry</button></div>';
  }
}

function cfdBuildHTML(t) {
  const pct = t.budget > 0 ? Math.min(100, (t.totalCollected / t.budget * 100)).toFixed(1) : '0.0';
  let dlDate = '—', dlNote = '';
  if (t.paymentDeadline) {
    const dl = new Date(t.paymentDeadline);
    if (!isNaN(dl)) {
      dlDate = dl.toLocaleDateString();
      const today = new Date(); today.setHours(0,0,0,0);
      const dlm = new Date(dl); dlm.setHours(0,0,0,0);
      const days = Math.round((dlm - today) / 86400000);
      dlNote = days > 0 ? `${days} day${days===1?'':'s'} remaining` : days === 0 ? 'Due today' : `${Math.abs(days)} day${Math.abs(days)===1?'':'s'} overdue`;
    }
  }
  const hasBudget = t.budget > 0;
  const gap = hasBudget ? Math.max(0, t.budget - t.totalCollected) : null;
  const CIRC = 503;
  const arcOf = $ => hasBudget ? ($ / t.budget) * CIRC : 0;
  const cArc = Math.min(arcOf(t.totalCollected), CIRC);
  const oArc = Math.min(arcOf(t.balanceRemaining), CIRC - cArc);
  const pArc = Math.max(0, CIRC - cArc - oArc);
  const pAmt = hasBudget ? Math.max(0, t.budget - t.totalCollected - t.balanceRemaining) : 0;

  return `
    <div class="cfd-metrics">
      <div class="cfd-metric budget">
        <div class="cfd-micon">📄</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Team Budget</span><span class="cfd-mval">${cfdMoney(t.budget)}</span>${t.budget===0?'<span class="cfd-msub">No budget set</span>':''}</div>
      </div>
      <div class="cfd-metric">
        <div class="cfd-micon ic">👥</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Players Registered &amp; Paid</span><span class="cfd-mval">${t.goodStanding} / ${t.totalRegistered}</span><span class="cfd-msub">fully paid / total registered</span></div>
      </div>
      <div class="cfd-metric">
        <div class="cfd-micon col">💵</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Total Revenue Collected</span><span class="cfd-mval">${cfdMoney(t.totalCollected)}</span>${hasBudget?`<span class="cfd-msub">${pct}% of budget</span>`:''}</div>
      </div>
      <div class="cfd-metric">
        <div class="cfd-micon bal">📈</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Balance to Meet Budget</span><span class="cfd-mval">${hasBudget ? cfdMoney(gap) : '—'}</span><span class="cfd-msub">${!hasBudget?'No budget set':gap===0?'✓ Budget reached':dlNote||'remaining'}</span></div>
      </div>
      <div class="cfd-metric">
        <div class="cfd-micon ok">✅</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Good Standing</span><span class="cfd-mval">${t.goodStanding}</span><span class="cfd-msub">Fully paid players</span></div>
      </div>
      <div class="cfd-metric alert">
        <div class="cfd-micon red">⚠️</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Accounts in Red</span><span class="cfd-mval">${t.deadlinePassed ? t.accountsInRed : '—'}</span>${!t.paymentDeadline?'<span class="cfd-msub">No deadline set</span>':!t.deadlinePassed?'<span class="cfd-msub">Deadline not passed yet</span>':t.accountsInRed>0?'<span class="cfd-msub">Players with overdue balance</span>':'<span class="cfd-msub">✓ All accounts paid</span>'}</div>
      </div>
      <div class="cfd-metric">
        <div class="cfd-micon bal">💳</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Outstanding Balance</span><span class="cfd-mval">${cfdMoney(t.balanceRemaining)}</span><span class="cfd-msub">across registered players</span></div>
      </div>
      <div class="cfd-metric">
        <div class="cfd-micon dl">📅</div>
        <div class="cfd-mbody"><span class="cfd-mlabel">Collection Deadline</span><span class="cfd-mval">${dlDate}</span>${dlNote?`<span class="cfd-msub">${cfdEsc(dlNote)}</span>`:''}</div>
      </div>
    </div>

    ${hasBudget ? `
    <div class="cfd-chart-standalone">
      <span class="cfd-mlabel" style="display:block;margin-bottom:.8rem">Budget Progress</span>
      <div class="cfd-pie-wrap">
        <svg viewBox="0 0 200 200">
          <circle cx="100" cy="100" r="80" fill="none" stroke="#dde2ea" stroke-width="36"/>
          <circle class="cfd-seg" cx="100" cy="100" r="80" fill="none" stroke="#16a34a" stroke-width="36" stroke-dasharray="${cArc} ${CIRC}" transform="rotate(-90 100 100)" data-name="Collected" data-amount="${t.totalCollected}" data-pct="${(t.totalCollected/t.budget*100).toFixed(1)}"/>
          <circle class="cfd-seg" cx="100" cy="100" r="80" fill="none" stroke="#c8102e" stroke-width="36" stroke-dasharray="${oArc} ${CIRC}" stroke-dashoffset="${-cArc}" transform="rotate(-90 100 100)" data-name="Owed by players" data-amount="${t.balanceRemaining}" data-pct="${(t.balanceRemaining/t.budget*100).toFixed(1)}"/>
          <circle class="cfd-seg" cx="100" cy="100" r="80" fill="none" stroke="#b45309" stroke-width="36" stroke-dasharray="${pArc} ${CIRC}" stroke-dashoffset="${-(cArc+oArc)}" transform="rotate(-90 100 100)" data-name="Pending to budget" data-amount="${pAmt}" data-pct="${(pAmt/t.budget*100).toFixed(1)}"/>
          <text x="100" y="95"  text-anchor="middle" font-size="26" font-weight="700" font-family="Oswald" fill="#0d1f38">${pct}%</text>
          <text x="100" y="116" text-anchor="middle" font-size="10" font-family="Oswald" letter-spacing="2" fill="#7a8499">COLLECTED</text>
        </svg>
        <div class="cfd-pie-tt" id="cfd-pie-tt"><span class="ptt-lbl"></span><span class="ptt-amt"></span><span class="ptt-pct"></span></div>
      </div>
      <div class="cfd-legend">
        <div class="cfd-leg-item"><span class="cfd-leg-dot" style="background:#16a34a"></span><span>Collected: ${cfdMoney(t.totalCollected)}</span></div>
        <div class="cfd-leg-item"><span class="cfd-leg-dot" style="background:#c8102e"></span><span>Owed: ${cfdMoney(t.balanceRemaining)}</span></div>
        <div class="cfd-leg-item"><span class="cfd-leg-dot" style="background:#b45309"></span><span>Pending: ${cfdMoney(pAmt)}</span></div>
      </div>
    </div>` : ''}

    <div class="cfd-section">
      <div class="cfd-section-head">
        <h3>Player Financial Accounts</h3>
        <div class="cfd-controls">
          <div class="cfd-search"><span>🔍</span><input type="text" placeholder="Search players…" id="cfd-search" oninput="cfdOnFilter()"/></div>
          <select class="cfd-filter" id="cfd-filter" onchange="cfdOnFilter()">
            <option value="all">All Players</option>
            <option value="paid">Paid in Full</option>
            <option value="partial">Partial</option>
          </select>
        </div>
      </div>
      <div style="overflow-x:auto;">
        <table class="cfd-tbl">
          <thead><tr><th>Player Name</th><th>Total Fee</th><th>Paid Amount</th><th>Balance Due</th><th>Last Payment</th><th>Status</th></tr></thead>
          <tbody id="cfd-tbody"><tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--sub);">Loading…</td></tr></tbody>
        </table>
      </div>
      <div class="cfd-pag" id="cfd-pag"></div>
    </div>`;
}

async function cfdLoadPlayers() {
  const searchEl = document.getElementById('cfd-search');
  const filterEl = document.getElementById('cfd-filter');
  const search = searchEl ? searchEl.value.trim() : '';
  const status = filterEl ? filterEl.value : 'all';
  const tbody  = document.getElementById('cfd-tbody');
  const pag    = document.getElementById('cfd-pag');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--sub);">Loading…</td></tr>`;
  const qs = new URLSearchParams({ page: _cfdPag.page, perPage: _cfdPag.perPage });
  if (search) qs.set('search', search);
  if (status && status !== 'all') qs.set('status', status);
  let result;
  try { result = await cfdApiFetch(`/api/coach/fin/players?${qs}`); }
  catch(e) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--red);">${cfdEsc(e.message||'Failed')}</td></tr>`;
    if (pag) pag.innerHTML = '';
    return;
  }
  const { players, total } = result;
  const totalPages = Math.max(1, Math.ceil(total / _cfdPag.perPage));
  if (_cfdPag.page > totalPages) { _cfdPag.page = totalPages; return cfdLoadPlayers(); }
  tbody.innerHTML = players.length === 0
    ? `<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--sub);">No players match your filters.</td></tr>`
    : players.map(p => `
        <tr>
          <td class="t-name">${cfdEsc(p.name)}</td>
          <td>${cfdMoney(p.totalFee)}</td>
          <td class="t-paid">${cfdMoney(p.paidAmount)}</td>
          <td class="t-bal">${cfdMoney(p.balance)}</td>
          <td>${cfdDate(p.lastPayment)}</td>
          <td><span class="cfd-sbadge ${p.status}">${p.status==='paid'?'Paid':p.status==='partial'?'Partial':'Unpaid'}</span></td>
        </tr>`).join('');
  if (pag) {
    pag._pg = np => { _cfdPag.page = np; cfdLoadPlayers(); };
    pag.innerHTML = `
      <div class="cfd-pag-info">Page ${_cfdPag.page} of ${totalPages} &middot; ${total} total</div>
      <div class="cfd-pag-btns">
        <button class="cfd-pbtn" ${_cfdPag.page<=1?'disabled':''} onclick="this.closest('.cfd-pag')._pg(${_cfdPag.page-1})">Prev</button>
        <button class="cfd-pbtn cur">${_cfdPag.page}</button>
        <button class="cfd-pbtn" ${_cfdPag.page>=totalPages?'disabled':''} onclick="this.closest('.cfd-pag')._pg(${_cfdPag.page+1})">Next</button>
      </div>`;
  }
}

let _cfdFilterTimer = null;
function cfdOnFilter() {
  _cfdPag.page = 1;
  clearTimeout(_cfdFilterTimer);
  _cfdFilterTimer = setTimeout(cfdLoadPlayers, 250);
}

function cfdBindChart() {
  const tt = document.getElementById('cfd-pie-tt');
  if (!tt) return;
  const lbl = tt.querySelector('.ptt-lbl'), amt = tt.querySelector('.ptt-amt'), pct = tt.querySelector('.ptt-pct');
  const host = tt.parentElement;
  document.querySelectorAll('#cfd-content .cfd-seg').forEach(seg => {
    seg.addEventListener('mouseenter', () => {
      lbl.textContent = seg.dataset.name; amt.textContent = cfdMoney(seg.dataset.amount); pct.textContent = `· ${seg.dataset.pct}% of budget`; tt.classList.add('show');
    });
    seg.addEventListener('mousemove', e => {
      const r = host.getBoundingClientRect();
      let x = e.clientX - r.left + 12, y = e.clientY - r.top + 12;
      if (x + tt.offsetWidth  > r.width)  x = e.clientX - r.left - tt.offsetWidth  - 12;
      if (y + tt.offsetHeight > r.height) y = e.clientY - r.top  - tt.offsetHeight - 12;
      tt.style.left = `${Math.max(0,x)}px`; tt.style.top = `${Math.max(0,y)}px`;
    });
    seg.addEventListener('mouseleave', () => tt.classList.remove('show'));
  });
}
</script>
<!-- BUDGET VIEW MODAL -->
<div class="edit-overlay" id="budget-view-overlay">
  <div class="edit-modal" style="max-width:600px">
    <div class="edit-modal-head">
      <h3 id="bv-name">Budget Details</h3>
      <button class="edit-modal-close" onclick="closeBudgetView()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    </div>
    <div class="edit-modal-body" style="max-height:70vh;overflow-y:auto">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem .8rem;margin-bottom:1rem">
        <div style="background:var(--light);border-radius:6px;padding:.6rem .9rem">
          <div style="font-size:.62rem;color:var(--sub);text-transform:uppercase;letter-spacing:.1em">Paying Players</div>
          <div style="font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:var(--navy)" id="bv-players">—</div>
        </div>
        <div style="background:var(--light);border-radius:6px;padding:.6rem .9rem">
          <div style="font-size:.62rem;color:var(--sub);text-transform:uppercase;letter-spacing:.1em">Seasons</div>
          <div style="font-family:'Oswald',sans-serif;font-size:1.1rem;font-weight:700;color:var(--navy)" id="bv-seasons">—</div>
        </div>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:.84rem">
        <thead><tr style="background:var(--navy)">
          <th style="padding:8px 12px;text-align:left;font-family:Oswald,sans-serif;font-size:.7rem;color:#fff;letter-spacing:.1em;text-transform:uppercase">Expense</th>
          <th style="padding:8px 12px;text-align:right;font-family:Oswald,sans-serif;font-size:.7rem;color:#fff;letter-spacing:.1em;text-transform:uppercase">Amount</th>
        </tr></thead>
        <tbody>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Tournaments / Events</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-events"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Head Coach Pay</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-head"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Assistant Coach Pay</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-asst"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Rentals</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-rentals"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Hotel Costs</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-hotel"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Gas</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-gas"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Coach Uniforms</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-uniforms"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Equipment</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-equipment"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Coach Liability Insurance</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-insurance"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px">Ambassadors Baseball</td><td style="padding:8px 12px;text-align:right;font-weight:600" id="bv-ambassadors"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px" id="bv-other1"></td><td style="padding:8px 12px;text-align:right;font-weight:600"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px" id="bv-other2"></td><td style="padding:8px 12px;text-align:right;font-weight:600"></td></tr>
          <tr style="border-bottom:1px solid var(--mid)"><td style="padding:8px 12px" id="bv-other3"></td><td style="padding:8px 12px;text-align:right;font-weight:600"></td></tr>
          <tr style="background:var(--navy)"><td style="padding:10px 12px;font-family:Oswald,sans-serif;font-weight:700;color:#fff;letter-spacing:.05em">TOTAL EXPENSES</td><td style="padding:10px 12px;text-align:right;font-family:Oswald,sans-serif;font-size:1.05rem;font-weight:700;color:#f5c518" id="bv-total"></td></tr>
        </tbody>
      </table>
      <div class="budget-player-fee" style="margin-top:1rem">
        <span class="budget-player-fee-label">Player Fee (Total ÷ Paying Players)</span>
        <span class="budget-player-fee-value" id="bv-fee"></span>
      </div>
    </div>
    <div class="edit-modal-foot">
      <button class="edit-cancel-btn" onclick="closeBudgetView()">Close</button>
    </div>
  </div>
</div>

<!-- EDIT TRYOUT MODAL -->
<div class="edit-overlay" id="tryout-edit-overlay">
  <div class="edit-modal">
    <div class="edit-modal-head">
      <h3>Edit Tryout</h3>
      <button class="edit-modal-close" onclick="closeEditTryoutModal()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    </div>
    <div class="edit-modal-body">
      <input type="hidden" id="et-id">
      <input type="hidden" id="et-time">
      <div class="edit-modal-grid">
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Date</label>
          <div class="date-input-wrap">
            <input class="field-input" type="text" id="et-date" placeholder="e.g. June 10, 2026">
            <span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg></span>
          </div>
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Time</label>
          <div style="display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:.5rem;">
            <div class="date-input-wrap">
              <input class="field-input" type="text" id="et-time-start" placeholder="Start Time">
              <span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></span>
            </div>
            <span style="color:var(--sub);font-size:.82rem;white-space:nowrap;font-weight:600;">to</span>
            <div class="date-input-wrap">
              <input class="field-input" type="text" id="et-time-end" placeholder="End Time">
              <span class="cal-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></span>
            </div>
          </div>
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Location / Field Name</label>
          <input class="field-input" type="text" id="et-location" placeholder="e.g. Westside Sports Complex">
        </div>
        <div class="field-group" style="grid-column:1/-1">
          <label class="field-label">Tryout Fee</label>
          <div id="et-fee-container">
            <select class="field-select" id="et-fee-type" onchange="toggleFeeAmount()">
              <option value="free">Free</option>
              <option value="fee">Fee</option>
            </select>
          </div>
        </div>
        <div class="field-group">
          <label class="field-label">City</label>
          <input class="field-input" type="text" id="et-city" placeholder="e.g. Nashville">
        </div>
        <div class="field-group">
          <label class="field-label">State</label>
          <input class="field-input" type="text" id="et-state" placeholder="e.g. TN" maxlength="2">
        </div>
      </div>
    </div>
    <div class="edit-modal-foot">
      <button class="edit-cancel-btn" onclick="closeEditTryoutModal()">Cancel</button>
      <button class="edit-save-btn" id="et-save-btn" onclick="saveEditTryout()">Save Changes</button>
    </div>
  </div>
</div>
<!-- PUBLISH CONFIRM MODAL -->
<div class="edit-overlay" id="publish-confirm-overlay">
  <div class="edit-modal" style="max-width:480px">
    <div class="edit-modal-head" style="background:var(--navy)">
      <h3>Confirm Publish</h3>
      <button class="edit-modal-close" onclick="closePublishConfirm()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    </div>
    <div class="edit-modal-body">
      <p id="publish-confirm-msg" style="font-size:.88rem;line-height:1.65;color:var(--text)"></p>
    </div>
    <div class="edit-modal-foot">
      <button class="edit-cancel-btn" onclick="closePublishConfirm()">Cancel</button>
      <button class="budget-publish-btn" id="publish-confirm-ok-btn" onclick="_publishConfirmCallback && _publishConfirmCallback()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px;height:14px"><path d="M5 12l5 5L20 7"/></svg>
        Confirm Publish
      </button>
    </div>
  </div>
</div>
</body>
</html>
