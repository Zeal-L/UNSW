export function extractUId(token) {
  let u_id = localStorage.getItem('u_id');
  if (u_id == null) {
  	u_id = -1;
  }
  return u_id;
}
