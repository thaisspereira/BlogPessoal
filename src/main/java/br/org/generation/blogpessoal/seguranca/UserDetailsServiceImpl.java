package br.org.generation.blogpessoal.seguranca;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.org.generation.blogpessoal.model.Usuario;
import br.org.generation.blogpessoal.repository.UsuarioRepository;


@Service
public class UserDetailsServiceImpl implements UserDetailsService{
	
	@Autowired
	private UsuarioRepository usuarioRespository;
	
	@Override
	public UserDetails loadUserByUsername(String usuarioName) throws UsernameNotFoundException {
	Optional<Usuario> usuario = usuarioRespository.findByUsuario(usuarioName);
	     usuario.orElseThrow(()-> new UsernameNotFoundException(usuarioName + "not found."));
	     
	     return usuario.map(UserDetailsImpl :: new).get();
	}

}
